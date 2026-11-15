"""Reproducible source delivery, or private plugin for a verified remote server."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parent
EXCLUDED = {"__pycache__", ".pytest_cache", "state", "secrets", "private", "node_modules"}
SUFFIXES = {".py", ".json", ".md", ".css", ".js", ".svg", ".png", ".toml", ".lock", ".sh", ".service", ".conf", ".example", ".yml", ".go", ".proto", ".patch", ".txt"}
PLUGIN_FILES = ("plugin.json", "assets/icon.png", "skills/tesla-personal/SKILL.md")


def source_inputs(root):
    paths = [root/n for n in ("AGENTS.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "VERSION", "README.md", "project.json", "pyproject.toml", "requirements.lock", "requirements-test.lock", "build.py")]
    for folder in ("src/tesla_plugin", "tests", "tools", "docs", "deploy", "plugin"):
        for path in (root/folder).rglob("*"):
            if any(p in EXCLUDED or p.endswith(".egg-info") for p in path.relative_to(root).parts):
                continue
            if path.is_symlink():
                raise ValueError("Symlinks are not package inputs")
            if path.is_file() and path.suffix in SUFFIXES:
                paths.append(path)
    return paths


def archive(output, entries):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be new; existing artifacts are preserved")
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in entries.items()}
    entries = {**entries, "SHA256SUMS.json": (json.dumps(manifest, sort_keys=True, indent=2)+"\n").encode()}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            target.writestr(info, data, compresslevel=9)
    with zipfile.ZipFile(output) as check:
        if check.testzip() or set(check.namelist()) != set(entries):
            raise ValueError("Archive integrity check failed")
    return hashlib.sha256(output.read_bytes()).hexdigest()


def source(root, output):
    entries = {}
    for path in source_inputs(root):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Expected a regular source input")
        entries[path.relative_to(root).as_posix()] = path.read_bytes()
    return archive(output, entries)


def verify_endpoint(url, issuer, token):
    """Read-only OAuth resource and authenticated tool discovery; no Tesla calls."""
    import httpx
    from tesla_plugin.config import https_url
    https_url(url)
    https_url(issuer)
    if not isinstance(token, str) or len(token)>16384 or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
        raise ValueError("Verification requires a JWT access token without whitespace")
    parsed = urlsplit(url)
    if not parsed.path.endswith("/mcp"):
        raise ValueError("Expected the configured MCP resource URL")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    with httpx.Client(timeout=10, follow_redirects=False, verify=ssl.create_default_context()) as client:
        def fetch(method, endpoint, **kwargs):
            with client.stream(method, endpoint, **kwargs) as response:
                if response.status_code != 200:
                    raise ValueError("Remote verification was not successful")
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 2_000_000:
                        raise ValueError("Remote verification response too large")
                    chunks.append(chunk)
                return json.loads(b"".join(chunks))
        metadata = fetch("GET", origin+"/.well-known/oauth-protected-resource"+parsed.path)
        if metadata.get("resource") != url or metadata.get("authorization_servers") != [issuer]:
            raise ValueError("Remote OAuth resource or issuer differs from package configuration")
        result = fetch("POST", url,
            headers={"Authorization": "Bearer "+token, "Accept": "application/json, text/event-stream",
                     "MCP-Protocol-Version": "2026-07-28", "MCP-Method": "tools/list"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}})
        names = {tool["name"] for tool in result.get("result", {}).get("tools", [])}
        from tesla_plugin.server import TOOLS
        if names != set(TOOLS):
            raise ValueError("Remote tool inventory differs from the source package")
        return {"resource": url, "issuer": issuer, "verified_tools": len(names), "vehicle_tested": False}


def verify_onboarding_endpoint(url, issuer):
    """Verify a deployed, closed pilot before the owner connects it in ChatGPT.

    OAuth consent cannot precede the plugin connection in every host. This
    branch verifies discovery and authentication enforcement, never pretends
    that anonymous discovery proves authenticated tools or event delivery.
    """
    import httpx
    from tesla_plugin.config import https_url
    https_url(url)
    https_url(issuer)
    parsed = urlsplit(url)
    if not parsed.path.endswith("/mcp"):
        raise ValueError("Expected the configured MCP resource URL")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    resource_path = "/.well-known/oauth-protected-resource"+parsed.path
    with httpx.Client(timeout=10, follow_redirects=False, verify=ssl.create_default_context()) as client:
        def fetch(endpoint):
            with client.stream("GET", endpoint) as response:
                if response.status_code != 200:
                    raise ValueError("Onboarding discovery was not successful")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 262144:
                        raise ValueError("Onboarding discovery response too large")
                return json.loads(body)
        metadata = fetch(origin+resource_path)
        if metadata.get("resource") != url or metadata.get("authorization_servers") != [issuer]:
            raise ValueError("Remote OAuth resource or issuer differs from package configuration")
        oidc = fetch(issuer+"/.well-known/openid-configuration")
        if (oidc.get("issuer") != issuer or "S256" not in oidc.get("code_challenge_methods_supported", [])
                or "none" not in oidc.get("token_endpoint_auth_methods_supported", [])):
            raise ValueError("Issuer does not advertise the required public PKCE client")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            https_url(oidc.get(key, ""))
        health = fetch(url[:-4]+"/healthz")
        if health.get("process") != "running" or health.get("live_enabled") is not False:
            raise ValueError("Initial onboarding requires a running pilot with live requests disabled")
        with client.stream("POST", url, headers={"Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28", "MCP-Method": "tools/list"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) as response:
            challenge = response.headers.get("www-authenticate", "")
            if response.status_code != 401 or not challenge.startswith("Bearer ") or "resource_metadata=" not in challenge:
                raise ValueError("Pilot must require OAuth authentication")
    from tesla_plugin.server import TOOLS
    return {"resource": url, "issuer": issuer, "endpoint_verified": True, "source_tools": len(TOOLS),
            "authenticated_discovery_verified": False, "owner_connection_required": True,
            "native_events_verified": False, "vehicle_tested": False}


def plugin(root, output, url, issuer, client_id, token_file=None, *, await_user_auth=False, pilot=False):
    from tesla_plugin.config import secret, SCOPES
    if pilot and not await_user_auth:
        raise ValueError("Pilot labelling requires the initial live-disabled onboarding verification")
    if await_user_auth:
        if token_file is not None or not pilot:
            raise ValueError("Initial owner connection is reserved for a labelled pilot without a token file")
        verified = verify_onboarding_endpoint(url, issuer)
    else:
        verified = verify_endpoint(url, issuer, secret(token_file))
    manifest = json.loads((root/"plugin/plugin.json").read_text())
    interface = manifest["extensions"]["com.openai"]["interface"]
    if manifest["version"] != (root/"VERSION").read_text().strip() or len(interface["shortDescription"]) > 30:
        raise ValueError("Plugin identity and version are inconsistent")
    if not re.fullmatch(r"[A-Za-z0-9._~:/-]{1,256}", client_id):
        raise ValueError("Use the real client ID registered with the MCP authorization server")
    if any(any(p.is_symlink() for p in (root/"plugin"/name, *(root/"plugin"/name).parents)) for name in PLUGIN_FILES):
        raise ValueError("Symlinks are not package inputs")
    entries = {name: (root/"plugin"/name).read_bytes() for name in PLUGIN_FILES}
    for notice_name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
        path = root/notice_name
        if path.is_symlink() or not path.is_file():
            raise ValueError("License notices must be regular source files")
        entries[notice_name] = path.read_bytes()
    if pilot:
        interface["displayName"] = "TESLA · Test"
        interface["shortDescription"] = 'Synthetic test instance'
        interface["longDescription"] = 'Isolated instance for testing ChatGPT tools and notifications with synthetic data. No vehicle is connected and live Tesla requests are disabled.'
        interface["defaultPrompt"] = 'Check the TESLA connection and show test vehicles without live refreshes.'
        entries["plugin.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2)+"\n").encode()
        entries["skills/tesla-personal/SKILL.md"] += ('\n\nThis installation is a TEST with synthetic data. Do not describe it as real vehicle data. Use `tesla_list_vehicles` with `refresh=false`. OAuth connects the test service, not a Tesla account. Do not suggest vehicle commands or Tesla account linking during this test. Authenticated discovery and native events require verification after connecting the service in ChatGPT.\n').encode()
    entries["mcp.json"] = (json.dumps({"$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", "mcpServers": {
        "tesla-personal": {"type": "streamable-http", "url": url, "extensions": {"com.openai": {"auth": {
            "type": "oauth", "client": {"mode": "provided", "clientId": client_id, "tokenEndpointAuthMethod": "none"},
            "baseScopes": ["openid", "offline_access", "tesla:read"],
            "defaultScopes": ["openid", "offline_access", *SCOPES]}}}}}}, indent=2)+"\n").encode()
    return {"sha256": archive(output, entries), "verification": verified}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kind", choices=("source", "plugin"), default="source")
    parser.add_argument("--mcp-url")
    parser.add_argument("--issuer")
    parser.add_argument("--oauth-client-id")
    parser.add_argument("--mcp-token-file", type=Path)
    parser.add_argument("--await-user-auth", action="store_true", help="Verify the deployed closed pilot; owner connects through ChatGPT afterwards")
    parser.add_argument("--pilot", action="store_true", help="Label the private plugin and skill as synthetic testing")
    args = parser.parse_args(argv)
    if args.kind == "source":
        result = {"source_archive_sha256": source(ROOT, args.output), "installed": False}
    else:
        if not all((args.mcp_url, args.issuer, args.oauth_client_id)) or not (args.mcp_token_file or args.await_user_auth):
            parser.error("Private plugin requires its deployed endpoint, issuer, client ID and either a private token file or initial pilot connection")
        result = plugin(ROOT, args.output, args.mcp_url, args.issuer, args.oauth_client_id, args.mcp_token_file,
                        await_user_auth=args.await_user_auth, pilot=args.pilot)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
