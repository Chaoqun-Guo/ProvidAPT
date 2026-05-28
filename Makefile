.PHONY: all build ebpf userspace install clean test
.PHONY: verify-env install-deps deps
.PHONY: run stop attack-sim verify-capture

SHELL := /bin/bash

# --- Toolchain -------------------------------------------------
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
GO         ?= go

# --- Paths ----------------------------------------------------
BPF_SRC  := kernel/bpf
OUTPUT   := build
EBPF_OUT := $(OUTPUT)/ebpf
BIN_OUT  := $(OUTPUT)/bin
CONFIG   := /etc/providapt

# --- eBPF compilation flags -----------------------------------
BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_CFLAGS  += -I$(BPF_SRC)/../include
BPF_CFLAGS  += -Wall -Werror
BPF_CFLAGS  += -mlittle-endian

# Detect architecture for BPF target
BPF_ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/armv7l/arm/')
BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(shell echo $(BPF_ARCH) | tr a-z A-Z)
BPF_CFLAGS  += -I$(BPF_SRC)/../include -Wall -Werror
BPF_CFLAGS  += -mlittle-endian

# ==============================================================
# Build targets
# ==============================================================

all: build

build: ebpf userspace
	@echo "✓ Build complete: $(BIN_OUT)/providaptd"

ebpf:
	@mkdir -p $(EBPF_OUT)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC)/lsm_hooks.bpf.c  -o $(EBPF_OUT)/lsm_hooks.bpf.o
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC)/defense.bpf.c   -o $(EBPF_OUT)/defense.bpf.o
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC)/memory.bpf.c    -o $(EBPF_OUT)/memory.bpf.o
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC)/network.bpf.c   -o $(EBPF_OUT)/network.bpf.o
	$(LLVM_STRIP) -g $(EBPF_OUT)/lsm_hooks.bpf.o $(EBPF_OUT)/defense.bpf.o $(EBPF_OUT)/memory.bpf.o $(EBPF_OUT)/network.bpf.o
	@echo "✓ eBPF: lsm_hooks + defense + memory + network"

userspace:
	@mkdir -p $(BIN_OUT)
	$(GO) build -o $(BIN_OUT)/providaptd        ./userspace/cmd/providaptd
	$(GO) build -o $(BIN_OUT)/providaptctl      ./userspace/cmd/providaptctl
	$(GO) build -o $(BIN_OUT)/providapt-watchdog ./userspace/cmd/providapt-watchdog
	$(GO) build -o $(BIN_OUT)/providapt-verify   ./userspace/cmd/providapt-verify
	$(GO) build -o $(BIN_OUT)/providapt-deanon   ./userspace/cmd/providapt-deanon
	$(GO) build -o $(BIN_OUT)/providapt-heal     ./userspace/cmd/providapt-heal
	@echo "✓ Userspace: providaptd + providaptctl + providapt-watchdog + providapt-verify + providapt-deanon + providapt-heal"

clean:
	rm -rf $(OUTPUT)
	@echo "✓ Cleaned"

# ==============================================================
# Testing
# ==============================================================

test:
	$(GO) test -v -race -count=1 ./...

test-short:
	$(GO) test -short -count=1 ./...

# ==============================================================
# System verification
# ==============================================================

verify-env:
	@bash scripts/verify.sh

install-deps deps:
	@bash scripts/install_deps.sh

# ==============================================================
# Install
# ==============================================================

install: build
	install -d $(CONFIG)
	install -d /usr/local/lib/providapt/ebpf
	install -m 0755 $(BIN_OUT)/providaptd        /usr/local/sbin/providaptd
	install -m 0755 $(BIN_OUT)/providaptctl      /usr/local/bin/providaptctl
	install -m 0755 $(BIN_OUT)/providapt-watchdog /usr/local/sbin/providapt-watchdog
	install -m 0644 $(EBPF_OUT)/lsm_hooks.bpf.o  /usr/local/lib/providapt/ebpf/
	install -m 0644 $(EBPF_OUT)/defense.bpf.o    /usr/local/lib/providapt/ebpf/
	install -m 0644 $(EBPF_OUT)/memory.bpf.o     /usr/local/lib/providapt/ebpf/
	install -m 0644 $(EBPF_OUT)/network.bpf.o    /usr/local/lib/providapt/ebpf/
	@test -f $(CONFIG)/providapt.toml || install -m 0644 scripts/providapt.toml $(CONFIG)/
	@echo "✓ Installed.  Start:  sudo providaptd"

uninstall:
	rm -f /usr/local/sbin/providaptd
	rm -f /usr/local/sbin/providapt-watchdog
	rm -f /usr/local/bin/providaptctl
	rm -rf /usr/local/lib/providapt
	@echo "✓ Uninstalled"

# ==============================================================
# Runtime control
# ==============================================================

run: build
	sudo $(BIN_OUT)/providaptd -config $(CONFIG)/providapt.toml

watch: build
	@echo "Starting watchdog (auto-restart enabled)..."
	sudo $(BIN_OUT)/providapt-watchdog -agent $(BIN_OUT)/providaptd

stop:
	sudo providaptctl -stop 2>/dev/null || sudo pkill providaptd 2>/dev/null || true
	@echo "✓ Stopped"

restart: stop run

deploy-prod:
	@sudo bash scripts/deploy_prod.sh

probe:
	@bash scripts/kernel_probe.sh

cgroup:
	@sudo bash scripts/setup_cgroup.sh

# ==============================================================
# Attack simulation & capture verification
# ==============================================================

attack-sim:
	@bash test/attack-scenarios/attack_sim.sh

verify-capture:
	@bash test/attack-scenarios/verify_capture.sh

# ==============================================================
# Docker
# ==============================================================

docker-build:
	docker build -t providapt:latest -f scripts/docker/Dockerfile.ubuntu .

docker-run: docker-build
	docker run --rm -it --privileged \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		providapt:latest

# ==============================================================
# Help
# ==============================================================

help:
	@echo 'ProvidAPT Makefile'
	@echo ''
	@echo 'Build:'
	@echo '  make build          Build eBPF + userspace binaries'
	@echo '  make ebpf           Compile eBPF bytecode only'
	@echo '  make userspace      Build Go binaries only'
	@echo '  make clean          Remove build artifacts'
	@echo ''
	@echo 'System:'
	@echo '  make verify-env     Check kernel config & dependencies'
	@echo '  make install-deps   Install libbpf/clang/kernel-headers'
	@echo '  make install        Build & install to system'
	@echo '  make uninstall      Remove installed files'
	@echo ''
	@echo 'Run:'
	@echo '  make run            Start ProvidAPT daemon'
	@echo '  make stop           Stop ProvidAPT daemon'
	@echo '  make restart         Restart daemon'
	@echo '  make watch           Start watchdog (auto-restart daemon)'
	@echo ''
	@echo 'Test:'
	@echo '  make test           Run unit tests'
	@echo '  make attack-sim     Simulate APT attack scenario'
	@echo '  make verify-capture Verify provenance chain capture'
	@echo ''
	@echo 'Docker:'
	@echo '  make docker-build   Build Docker image'
	@echo '  make docker-run     Run in Docker container'
