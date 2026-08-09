# ProvidAPT production-style container image.

FROM golang:1.25-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates clang llvm libelf-dev libbpf-dev make \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build-userspace
RUN make build-ebpf

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates bpftool iproute2 tini \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /var/log/providapt /var/lib/providapt /etc/providapt /usr/local/lib/providapt/ebpf \
  && useradd --system --no-create-home --uid 950 --shell /usr/sbin/nologin providapt

COPY --from=builder /src/build/bin/providaptd /usr/local/sbin/providaptd
COPY --from=builder /src/build/bin/providaptctl /usr/local/bin/providaptctl
COPY --from=builder /src/build/bin/providapt-watchdog /usr/local/sbin/providapt-watchdog
COPY --from=builder /src/build/bin/providapt-verify /usr/local/bin/providapt-verify
COPY --from=builder /src/build/bin/providapt-deanon /usr/local/bin/providapt-deanon
COPY --from=builder /src/build/bin/providapt-heal /usr/local/bin/providapt-heal
COPY --from=builder /src/build/bin/providapt-sign /usr/local/bin/providapt-sign
COPY --from=builder /src/build/ebpf/ /usr/local/lib/providapt/ebpf/
COPY build/providapt.toml /etc/providapt/providapt.toml

EXPOSE 18080 50051

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD providaptctl status || exit 1

VOLUME ["/var/log/providapt", "/var/lib/providapt", "/etc/providapt"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["providaptd", "-config", "/etc/providapt/providapt.toml"]
