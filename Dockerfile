# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM node:22-slim AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── Stage 2: Production ─────────────────────────────────────────────────────
FROM node:22-slim
WORKDIR /app

# better-sqlite3 needs this
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm rebuild better-sqlite3

COPY --from=builder /app/dist/ ./dist/

# Data directory for SQLite store
RUN mkdir -p /data && chown node:node /data
ENV QBO_MCP_DATA_DIR=/data

EXPOSE 3100
USER node

CMD ["node", "dist/index.js"]
