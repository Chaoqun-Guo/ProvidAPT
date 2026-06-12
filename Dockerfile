# ─── ProvidAPT Docker build ──────────────────────────────────────
# Stage 1: Build
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build daemon, CLI, and utility tools (Linux only)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providaptd ./cmd/agent/daemon/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providaptctl ./cmd/cli/providaptctl/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providapt-watchdog ./cmd/agent/watchdog/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providapt-verify ./cmd/cli/providapt-verify/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providapt-deanon ./cmd/cli/providapt-deanon/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/providapt-heal ./cmd/cli/providapt-heal/

# Build eBPF bytecode (requires clang + llvm)
RUN apk add --no-cache clang llvm
COPY cmd/bpf /src/cmd/bpf
RUN mkdir -p /build/ebpf && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/src/cmd/bpf/headers \
      -c /src/cmd/bpf/probes/lsm/lsm_hooks.bpf.c \
      -o /build/ebpf/lsm_hooks.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/src/cmd/bpf/headers \
      -c /src/cmd/bpf/probes/lsm/defense.bpf.c \
      -o /build/ebpf/defense.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/src/cmd/bpf/headers \
      -c /src/cmd/bpf/probes/task/memory.bpf.c \
      -o /build/ebpf/memory.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/src/cmd/bpf/headers \
      -c /src/cmd/bpf/probes/net/network.bpf.c \
      -o /build/ebpf/network.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/src/cmd/bpf/headers \
      -c /src/cmd/bpf/probes/lsm/deception.bpf.c \
      -o /build/ebpf/deception.bpf.o && \
    llvm-strip -g /build/ebpf/*.bpf.o 2>/dev/null || true

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
COPY --from=builder /build/providapt-verify /usr/local/bin/
COPY --from=builder /build/providapt-deanon /usr/local/bin/
COPY --from=builder /build/providapt-heal /usr/local/bin/
COPY --from=builder /build/ebpf/ /usr/local/lib/providapt/ebpf/

# Default config
COPY build/providapt.toml /etc/providapt/providapt.toml

EXPOSE 8080
EXPOSE 50051

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD providaptctl status || exit 1

VOLUME ["/var/log/providapt", "/etc/providapt"]

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["providaptd"]
