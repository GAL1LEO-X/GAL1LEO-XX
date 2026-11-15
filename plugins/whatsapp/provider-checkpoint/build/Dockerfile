FROM node@sha256:e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174 AS dependencies
WORKDIR /app
COPY waha/ ./
COPY gows-linux-amd64 /app/gows
# The optional CA is consumed directly by clients and never written to trust stores.
RUN --mount=type=secret,id=ca_bundle,target=/run/secrets/ca_bundle,mode=0444 \
    set -eu; \
    if [ -f /run/secrets/ca_bundle ]; then \
      export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle GIT_SSL_CAINFO=/run/secrets/ca_bundle; \
      printf 'Acquire::https::CaInfo "/run/secrets/ca_bundle";\n' > /tmp/apt-ca.conf; \
    else : > /tmp/apt-ca.conf; fi; \
    if [ -n "${HTTP_PROXY:-}" ]; then export YARN_HTTP_PROXY="$HTTP_PROXY"; fi; \
    if [ -n "${HTTPS_PROXY:-}" ]; then export YARN_HTTPS_PROXY="$HTTPS_PROXY"; fi; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/20260623T000000Z\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: https://snapshot.debian.org/archive/debian-security/20260623T000000Z\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' > /etc/apt/sources.list.d/debian.sources; \
    apt-get -c /tmp/apt-ca.conf update; \
    apt-get -c /tmp/apt-ca.conf install --no-install-recommends -y git python3 build-essential ca-certificates; \
    npm install --prefix /opt/yarn --ignore-scripts --no-audit --no-fund @yarnpkg/cli-dist@4.17.1; \
    PUPPETEER_SKIP_DOWNLOAD=True node /opt/yarn/node_modules/@yarnpkg/cli-dist/bin/yarn.js install --immutable; \
    echo '3e0f1688128c3d0618882de734a40598d19e9b647aff866b1ca9de201f198778  /app/gows' | sha256sum -c -; \
    chmod +x /app/gows /app/entrypoint.sh; \
    rm -rf /var/lib/apt/lists/* /root/.npm /tmp/apt-ca.conf /app/.yarn/cache

FROM node@sha256:e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174 AS runtime
WORKDIR /app
RUN --mount=type=secret,id=ca_bundle,target=/run/secrets/ca_bundle,mode=0444 \
    set -eu; \
    if [ -f /run/secrets/ca_bundle ]; then \
      printf 'Acquire::https::CaInfo "/run/secrets/ca_bundle";\n' > /tmp/apt-ca.conf; \
    else : > /tmp/apt-ca.conf; fi; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/20260623T000000Z\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: https://snapshot.debian.org/archive/debian-security/20260623T000000Z\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' > /etc/apt/sources.list.d/debian.sources; \
    apt-get -c /tmp/apt-ca.conf update; \
    apt-get -c /tmp/apt-ca.conf install --no-install-recommends -y libvips42=8.14.1-3+deb12u3 ffmpeg tini ca-certificates; \
    rm -rf /var/lib/apt/lists/* /tmp/apt-ca.conf
COPY --from=dependencies /app /app
# Normalize only staged production artifacts, independently of the host umask.
# Keep installed dependency modes intact and preserve the existing runtime user.
RUN set -eu; \
    chown 0:0 /app /app/gows /app/entrypoint.sh /app/package.json /app/yarn.lock /app/.yarnrc.yml /app/LICENSE; \
    chmod 0755 /app /app/gows /app/entrypoint.sh; \
    chmod 0644 /app/package.json /app/yarn.lock /app/.yarnrc.yml /app/LICENSE; \
    find /app/dist -type d -exec chown 0:0 {} + -exec chmod 0755 {} +; \
    find /app/dist -type f -exec chown 0:0 {} + -exec chmod 0644 {} +
ENV WHATSAPP_DEFAULT_ENGINE=GOWS WAHA_VERSION=CORE WAHA_APPS_ENABLED=false \
    WAHA_GOWS_PATH=/app/gows WAHA_GOWS_SOCKET=/tmp/gows.sock \
    WHATSAPP_START_SESSION="" WHATSAPP_RESTART_ALL_SESSIONS=false WAHA_WORKER_RESTART_SESSIONS=true \
    WAHA_DASHBOARD_ENABLED=false WHATSAPP_SWAGGER_ENABLED=false WAHA_RUN_XVFB=false \
    OTEL_SDK_DISABLED=true OTEL_TRACES_EXPORTER=none OTEL_METRICS_EXPORTER=none OTEL_LOGS_EXPORTER=none \
    GODEBUG=netdns=cgo
EXPOSE 3000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh"]
