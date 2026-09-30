# ---- web build ----
FROM node:22-alpine AS web
WORKDIR /app
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- rust build ----
FROM rust:1-bookworm AS backend
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p ddm-server

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates docker.io docker-compose-v2 util-linux curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=backend /app/target/release/ddm-server /usr/local/bin/ddm-server
COPY --from=web /app/dist /opt/ddm/web
COPY config.example.yaml /etc/ddm/config.yaml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ddm-server", "--config", "/etc/ddm/config.yaml", "serve"]
