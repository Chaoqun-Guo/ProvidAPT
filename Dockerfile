# ─── ProvidAPT Docker build ──────────────────────────────────────
# Stage 1: Build
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build daemon and CLI (Linux only, eBPF build tags where needed)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providaptd ./cmd/agent/daemon/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providaptctl ./cmd/cli/providaptctl/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providapt-watchdog ./cmd/watchdog/

# Stage 2: Runtime
FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    bpftool \
    iproute2 \
    tini

# Create runtime directories
RUN mkdir -p /var/log/providapt /etc/providapt /var/run

COPY --from=builder /build/providaptd /usr/local/bin/
COPY --from=builder /build/providaptctl /usr/local/bin/
COPY --from=builder /build/providapt-watchdog /usr/local/bin/

# Default config
COPY scripts/docker/providapt.toml /etc/providapt/providapt.toml

EXPOSE 8080
EXPOSE 50051

VOLUME ["/var/log/providapt", "/etc/providapt"]

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["providaptd"]
