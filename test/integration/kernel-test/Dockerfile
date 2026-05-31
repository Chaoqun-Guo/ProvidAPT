# ProvidAPT Kernel Compatibility Test Container
#
# Build:
#   docker build -t providapt-kernel-test -f test/kernel-test/Dockerfile .
#
# Run:
#   docker run --privileged -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     providapt-kernel-test
#
# For specific kernel testing with QEMU:
#   docker run --privileged --pid=host --net=host \
#     -v /lib/modules:/lib/modules:ro \
#     providapt-kernel-test

FROM golang:1.22 AS builder
WORKDIR /build
COPY . .
RUN make build 2>&1

FROM ubuntu:24.04
LABEL description="ProvidAPT Kernel Compatibility Test"

# Install test dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld bpftool \
    linux-tools-common linux-tools-generic \
    python3 curl git jq \
    && rm -rf /var/lib/apt/lists/*

# Copy ProvidAPT build
COPY --from=builder /build/build /opt/providapt/bin
COPY --from=builder /build/test/kernel-test /opt/providapt/test

# Copy scripts
COPY --from=builder /build/scripts /opt/providapt/scripts

ENV PATH="/opt/providapt/bin:${PATH}"

WORKDIR /opt/providapt

ENTRYPOINT ["bash", "test/kernel-test/run_tests.sh"]
