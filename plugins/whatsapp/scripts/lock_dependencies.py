"""Pin installed, resolved runtime/test dependencies without environment-specific local paths."""
import importlib.metadata as md
from pathlib import Path
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

root=Path(__file__).resolve().parents[1]
seen={}
def visit(name):
    name=canonicalize_name(name)
    if name in seen:
        return
    dist=md.distribution(name)
    seen[name]=dist.version
    for line in dist.requires or []:
        req=Requirement(line)
        if req.marker and not req.marker.evaluate({"extra":""}):
            continue
        visit(req.name)

for name in ("mcp","PyJWT","cryptography","httpx","uvicorn"):
    visit(name)
runtime=dict(seen)
visit("pytest")
def lines(values):
    return "".join(f'{n}=={v}'+ (' ; sys_platform == "win32"' if n=="pywin32" else "")+'\n' for n,v in sorted(values.items()))
(root/"requirements.lock").write_text("# Resolved 2026-10-11. Python 3.13/3.14.\n"+lines(runtime),encoding="utf-8")
(root/"requirements-test.lock").write_text("-r requirements.lock\n"+lines({k:v for k,v in seen.items() if k not in runtime}),encoding="utf-8")
print(f"Pinned {len(runtime)} runtime packages and {len(seen)-len(runtime)} test packages")

