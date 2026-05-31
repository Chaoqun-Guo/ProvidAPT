.PHONY: all build ebpf userspace install clean test
.PHONY: verify-env install-deps deps
.PHONY: run stop attack-sim verify-capture
.PHONY: v1 demo ext-test cluster-test graphsketch-test deception-test supplychain-test
	@echo '  make attack-sim      Simulate APT attack scenario'
	@echo '  make verify-capture  Verify provenance chain capture'

SHELL := /bin/bash

# --- Toolchain -------------------------------------------------
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
GO         ?= go

# --- Version paths --------------------------------------------
OUTPUT   := build
EBPF_OUT := $(OUTPUT)/ebpf
BIN_OUT  := $(OUTPUT)/bin
CONFIG   := /etc/providapt

# ==============================================================
# Versioned builds
# ==============================================================

all: v1

# ── v1 (production) ──────────────────────────────────────────

BPF_SRC := cmd/bpf/probes

v1: v1-ebpf v1-userspace
	@echo "✓ v1 build: $(BIN_OUT)/providaptd"

v1-ebpf:
	@mkdir -p $(EBPF_OUT)
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/lsm/lsm_hooks.bpf.c -o $(EBPF_OUT)/lsm_hooks.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/lsm/defense.bpf.c -o $(EBPF_OUT)/defense.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/task/memory.bpf.c -o $(EBPF_OUT)/memory.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/net/network.bpf.c -o $(EBPF_OUT)/network.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/lsm/deception.bpf.c -o $(EBPF_OUT)/deception.bpf.o
	$(LLVM_STRIP) -g $(EBPF_OUT)/*.bpf.o 2>/dev/null || true
	@echo "✓ v1 eBPF: lsm_hooks + defense + memory + network"

v1-userspace:
	@mkdir -p $(BIN_OUT)
	$(GO) build -o $(BIN_OUT)/providaptd        ./cmd/agent/daemon
	$(GO) build -o $(BIN_OUT)/providaptctl      ./cmd/cli/providaptctl
	$(GO) build -o $(BIN_OUT)/providapt-watchdog ./cmd/agent/watchdog
	$(GO) build -o $(BIN_OUT)/providapt-verify   ./cmd/cli/providapt-verify
	$(GO) build -o $(BIN_OUT)/providapt-deanon   ./cmd/cli/providapt-deanon
	$(GO) build -o $(BIN_OUT)/providapt-heal     ./cmd/cli/providapt-heal
	@echo "✓ v1 userspace: 6 binaries"

v1-install: v1
	install -d $(CONFIG)
	install -d /usr/local/lib/providapt/ebpf
	install -m 0755 $(BIN_OUT)/providaptd        /usr/local/sbin/providaptd
	install -m 0755 $(BIN_OUT)/providaptctl      /usr/local/bin/providaptctl
	install -m 0755 $(BIN_OUT)/providapt-watchdog /usr/local/sbin/providapt-watchdog
	install -m 0644 $(EBPF_OUT)/*.bpf.o          /usr/local/lib/providapt/ebpf/
	@test -f $(CONFIG)/providapt.toml || install -m 0644 build/providapt.toml $(CONFIG)/
	@echo "✓ v1 installed.  Start:  sudo providaptd"

v1-test:
	$(GO) test -v -count=1 ./internal/... ./pkg/... ./cmd/...

# ── Demo / Extended tests ────────────────────────────

demo:
	$(GO) build -o $(BIN_OUT)/providapt-demo ./cmd/collector/demo
	@echo "✓ demo build: $(BIN_OUT)/providapt-demo"

ext-test:
	$(GO) test -v -count=1 ./internal/engine/edgereduce/... ./internal/engine/graphquery/... ./internal/engine/profile/... ./internal/engine/ratelimit/... ./internal/storage/schema/... ./internal/storage/pebblestore/... ./internal/storage/grpcexport/... ./internal/policy/rulescanner/... ./internal/policy/selfheal/...

# ── Cluster / Stitcher tests ─────────────────────────

cluster-test:
	$(GO) test -v -count=1 ./internal/stitcher/... ./internal/policy/blastradius/... ./internal/policy/deception/... ./internal/policy/supplychain/... ./internal/engine/ja3/... ./internal/engine/memforensic/... ./internal/storage/graphdb/...

graphsketch-test:
	$(GO) test -v -count=1 ./internal/stitcher/graphsketch/...

deception-test:
	$(GO) test -v -count=1 ./internal/policy/deception/...

supplychain-test:
	@echo '  make attack-sim      Simulate APT attack scenario'
	@echo '  make verify-capture  Verify provenance chain capture'
	$(GO) test -v -count=1 ./internal/policy/supplychain/...

# ── Legacy aliases (default to v1) ───────────────────────────

build: v1
ebpf: v1-ebpf
userspace: v1-userspace
install: v1-install
test: v1-test

# ── Common ───────────────────────────────────────────────────

clean:
	rm -rf $(OUTPUT)
	@echo "✓ Cleaned"

verify-env:
	@bash build/verify.sh

install-deps deps:
	@bash build/install_deps.sh

run: v1
	sudo $(BIN_OUT)/providaptd -config $(CONFIG)/providapt.toml

stop:
	sudo providaptctl -stop 2>/dev/null || sudo pkill providaptd 2>/dev/null || true
	@echo "✓ Stopped"

restart: stop run

deploy-prod:
	@sudo bash build/deploy_prod.sh

probe:
	@bash build/kernel_probe.sh

cgroup:
	@sudo bash build/setup_cgroup.sh

attack-sim:
	@bash test/integration/attack-scenarios/attack_sim.sh

verify-capture:
	@bash test/integration/attack-scenarios/verify_capture.sh

docker-build:
	docker build -t providapt:latest -f build/docker/Dockerfile.ubuntu .

docker-run: docker-build
	docker run --rm -it --privileged \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		providapt:latest

# ==============================================================
# Help
# ==============================================================

help:
	@echo 'ProvidAPT — Makefile'
	@echo ''
	@echo 'Build:'
	@echo '  make v1              Build production — eBPF + userspace'
	@echo '  make v1-ebpf         Compile eBPF bytecode only'
	@echo '  make v1-userspace    Compile Go binaries only'
	@echo '  make v1-install      Build & install to system'
	@echo '  make demo            Build collector demo'
	@echo ''
	@echo 'Test:'
	@echo '  make v1-test         Run core unit tests'
	@echo '  make ext-test        Run extended engine/storage/policy tests'
	@echo '  make cluster-test    Run stitcher/cluster tests'
	@echo '  make graphsketch-test'
	@echo '  make deception-test'
	@echo '  make supplychain-test'
	@echo '  make attack-sim      Simulate APT attack scenario'
	@echo '  make verify-capture  Verify provenance chain capture'
	@echo ''
	@echo 'Aliases (default v1):'
	@echo '  make build           = make v1'
	@echo '  make install         = make v1-install'
	@echo '  make test            = make v1-test'
	@echo '  make run             Build & run daemon'
	@echo '  make stop            Stop daemon'
	@echo ''
	@echo 'System:'
	@echo '  make verify-env      Check kernel config & dependencies'
	@echo '  make install-deps    Install libbpf/clang/kernel-headers'
	@echo '  make deploy-prod     Full production deployment'
	@echo ''
