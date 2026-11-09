# Relay-only image.
#
# The image contains the relay process and nothing else: no desktop agent, no
# PTY/SDK/Codex dependencies and no build toolchain at runtime. The locked
# runtime dependencies live in deploy/relay (mysql2 for the optional account
# layer, ws for the relay itself).
#
# Build this locally only as an explicit override:
#   docker compose -f compose.yml -f compose.build.yml up -d --build
ARG NODE_VERSION=24
FROM node:${NODE_VERSION}-alpine

WORKDIR /app

COPY deploy/relay/package.json deploy/relay/package-lock.json ./
# Both dependencies are pure JavaScript, so no compiler or desktop libraries
# are needed. `--ignore-scripts` keeps postinstall hooks out of the image.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# src/relay/main.ts imports exactly these four source trees; anything the relay
# needs at runtime must live under one of them (see test/deployment-image.test.ts).
COPY src/shared ./src/shared
COPY src/relay ./src/relay
COPY src/db ./src/db
COPY src/oauth ./src/oauth

RUN mkdir -p /data && chown node:node /data

USER node
ENV NODE_ENV=production \
    PORT=8787 \
    HOST=0.0.0.0 \
    RELAY_KEY_FILE=/data/relay-key
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:8787/healthz', { signal: AbortSignal.timeout(4000) }).then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "src/relay/main.ts"]