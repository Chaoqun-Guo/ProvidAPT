.PHONY: all build build-core build-ebpf build-userspace generate-ebpf install install-local
.PHONY: clean test test-core test-race fmt fmt-check vet lint staticcheck
.PHONY: verify-env install-deps deps run stop restart deploy-prod probe cgroup
.PHONY: attack-sim verify-capture loader-smoke demo ext-test cluster-test
.PHONY: graphsketch-test deception-test supplychain-test sbom sbom-syft
.PHONY: fuzz fuzz-short coverage coverage-html bench-baseline test-e2e test-integration
.PHONY: dist dist-deb dist-rpm dist-tar dist-all release-commercial package-smoke-matrix create-user docker-build docker-run help

SHELL := /bin/bash

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
GO ?= go
GO_TAGS ?=
GO_TAG_ARGS := $(if $(strip $(GO_TAGS)),-tags "$(GO_TAGS)")

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X github.com/Chaoqun-Guo/ProvidAPT/internal/version.Version=$(VERSION) -X github.com/Chaoqun-Guo/ProvidAPT/internal/version.Commit=$(COMMIT) -X github.com/Chaoqun-Guo/ProvidAPT/internal/version.Date=$(DATE)"

OUTPUT := build
EBPF_OUT := $(OUTPUT)/ebpf
BIN_OUT := $(OUTPUT)/bin
CONFIG := /etc/providapt
BPF_SRC := cmd/bpf/probes
SBOM_OUT ?= build
FUZZ_TIME ?= 15s
COVER_DIR := $(OUTPUT)/coverage

all: build-core

build-core: build-ebpf build-userspace
	@echo "Built core product into $(BIN_OUT)"

build-ebpf:
	@mkdir -p $(EBPF_OUT)
	@if [ ! -s cmd/bpf/headers/vmlinux.h ] || grep -q "Placeholder - replace" cmd/bpf/headers/vmlinux.h; then \
		if command -v $(BPFTOOL) >/dev/null 2>&1 && [ -r /sys/kernel/btf/vmlinux ]; then \
			echo "Generating cmd/bpf/headers/vmlinux.h from kernel BTF"; \
			$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > cmd/bpf/headers/vmlinux.h; \
		else \
			echo "Missing real vmlinux.h and cannot generate one via bpftool"; \
			exit 1; \
		fi; \
	fi
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -Icmd/bpf/probes -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/lsm/lsm_hooks.bpf.c -o $(EBPF_OUT)/lsm_hooks.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -Icmd/bpf/probes -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/lsm/defense.bpf.c -o $(EBPF_OUT)/defense.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -Icmd/bpf/probes -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/task/memory.bpf.c -o $(EBPF_OUT)/memory.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -Icmd/bpf/probes -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/net/network.bpf.c -o $(EBPF_OUT)/network.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -Icmd/bpf/probes -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/lsm/deception.bpf.c -o $(EBPF_OUT)/deception.bpf.o
	$(CLANG) $(BPF_CFLAGS) -Icmd/bpf/headers -Icmd/bpf/probes -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 -Wall -Werror -mlittle-endian \
		-c $(BPF_SRC)/kprobe/fallback.bpf.c -o $(EBPF_OUT)/kprobe_fallback.bpf.o
	$(LLVM_STRIP) -g $(EBPF_OUT)/*.bpf.o 2>/dev/null || true
	@echo "Built eBPF objects into $(EBPF_OUT)"

generate-ebpf: build-ebpf
	$(GO) generate ./internal/engine/loader/
	@echo "Generated bpf2go bindings"

build-userspace:
	@mkdir -p $(BIN_OUT)
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providaptd ./cmd/agent/daemon
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providaptctl ./cmd/cli/providaptctl
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providapt-watchdog ./cmd/agent/watchdog
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providapt-verify ./cmd/cli/providapt-verify
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providapt-deanon ./cmd/cli/providapt-deanon
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providapt-heal ./cmd/cli/providapt-heal
	$(GO) build $(GO_TAG_ARGS) $(LDFLAGS) -o $(BIN_OUT)/providapt-sign ./cmd/cli/providapt-sign
	@echo "Built userspace binaries into $(BIN_OUT)"

install-local: create-user build-core
	install -d $(CONFIG)
	install -d /etc/default
	install -d /usr/local/lib/providapt/ebpf
	install -d /var/lib/providapt /var/log/providapt
	install -m 0755 $(BIN_OUT)/providaptd /usr/local/sbin/providaptd
	install -m 0755 $(BIN_OUT)/providaptctl /usr/local/bin/providaptctl
	install -m 0755 $(BIN_OUT)/providapt-watchdog /usr/local/sbin/providapt-watchdog
	install -m 0755 $(BIN_OUT)/providapt-verify /usr/local/bin/providapt-verify
	install -m 0755 $(BIN_OUT)/providapt-heal /usr/local/bin/providapt-heal
	install -m 0755 $(BIN_OUT)/providapt-deanon /usr/local/bin/providapt-deanon
	install -m 0644 $(EBPF_OUT)/*.bpf.o /usr/local/lib/providapt/ebpf/
	@test -f $(CONFIG)/providapt.toml || install -m 0644 build/providapt.toml $(CONFIG)/
	@test -f /etc/default/providapt || install -m 0644 deploy/linux/providapt.env /etc/default/providapt
	install -m 0644 deploy/linux/providapt.service /etc/systemd/system/providapt.service
	@systemctl daemon-reload 2>/dev/null || true
	@echo "Installed ProvidAPT locally"

test-core:
	@mkdir -p $(COVER_DIR)
	$(GO) test -v -count=1 -coverprofile=$(COVER_DIR)/core.out -covermode=atomic ./internal/... ./pkg/... ./cmd/...

build: build-core
install: install-local
test: test-core
ebpf: build-ebpf
userspace: build-userspace

demo:
	$(GO) build -o $(BIN_OUT)/providapt-demo ./cmd/collector/demo
	@echo "Built collector demo"

fmt:
	$(GO) fmt ./cmd/... ./internal/... ./pkg/...

fmt-check:
	@test -z "$(shell $(GO) fmt ./cmd/... ./internal/... ./pkg/...)" || (echo "go fmt found unformatted files"; exit 1)

vet:
	$(GO) vet ./cmd/... ./internal/... ./pkg/...

lint: vet fmt-check

test-race:
	@mkdir -p $(COVER_DIR)
	$(GO) test -race -count=1 -short -coverprofile=$(COVER_DIR)/race.out -covermode=atomic ./internal/... ./pkg/... ./cmd/...

coverage: test-core
	@echo "=== Generating Coverage Report ==="
	$(GO) tool cover -func=$(COVER_DIR)/core.out -o $(COVER_DIR)/coverage.txt
	@echo "Coverage summary:"
	@tail -5 $(COVER_DIR)/coverage.txt

coverage-html: test-core
	@mkdir -p $(COVER_DIR)
	$(GO) tool cover -html=$(COVER_DIR)/core.out -o $(COVER_DIR)/coverage.html
	$(GO) tool cover -func=$(COVER_DIR)/core.out -o $(COVER_DIR)/coverage.txt
	@echo "Coverage report: file://$(PWD)/$(COVER_DIR)/coverage.html"
	@echo "Coverage summary:"
	@tail -5 $(COVER_DIR)/coverage.txt

staticcheck:
	staticcheck ./cmd/... ./internal/... ./pkg/...

sbom: sbom-syft

sbom-syft:
	@if command -v syft &>/dev/null; then \
		syft dir:. --output spdx-json=$(SBOM_OUT)/providapt-source.spdx.json; \
		syft dir:. --output cyclonedx-json=$(SBOM_OUT)/providapt-source.cdx.json; \
	else \
		echo "syft not installed. Install from https://github.com/anchore/syft"; \
		exit 1; \
	fi

fuzz-ci:
	$(GO) test -fuzz=FuzzParseRawEvent -fuzztime=45s ./internal/engine/collector/
	$(GO) test -fuzz=FuzzParseEdgeKey -fuzztime=45s ./internal/storage/schema/
	$(GO) test -fuzz=FuzzParseNodeKey -fuzztime=45s ./internal/storage/schema/
	$(GO) test -fuzz=FuzzConfigLoad -fuzztime=45s ./pkg/config/
	$(GO) test -fuzz=FuzzMatchTaint -fuzztime=45s ./internal/engine/taint/
	$(GO) test -fuzz=FuzzParseQuery -fuzztime=45s ./internal/engine/query/
	$(GO) test -fuzz=FuzzHashHex -fuzztime=45s ./internal/engine/forensic/
	$(GO) test -fuzz=FuzzAnonymizeHashString -fuzztime=45s ./pkg/anonymize/
	$(GO) test -fuzz=FuzzEventTypeString -fuzztime=45s ./internal/engine/syscall/

fuzz-long:
	$(GO) test -fuzz=FuzzParseRawEvent -fuzztime=5m ./internal/engine/collector/
	$(GO) test -fuzz=FuzzParseEdgeKey -fuzztime=5m ./internal/storage/schema/
	$(GO) test -fuzz=FuzzParseNodeKey -fuzztime=5m ./internal/storage/schema/
	$(GO) test -fuzz=FuzzConfigLoad -fuzztime=5m ./pkg/config/
	$(GO) test -fuzz=FuzzMatchTaint -fuzztime=5m ./internal/engine/taint/
	$(GO) test -fuzz=FuzzParseQuery -fuzztime=5m ./internal/engine/query/
	$(GO) test -fuzz=FuzzHashHex -fuzztime=5m ./internal/engine/forensic/
	$(GO) test -fuzz=FuzzAnonymizeHashString -fuzztime=5m ./pkg/anonymize/
	$(GO) test -fuzz=FuzzEventTypeString -fuzztime=5m ./internal/engine/syscall/

fuzz-short:
	@mkdir -p $(COVER_DIR)
	$(GO) test -fuzz=FuzzParseRawEvent -fuzztime=10s -coverprofile=$(COVER_DIR)/fuzz_event.out -covermode=atomic ./internal/engine/collector/
	$(GO) test -fuzz=FuzzParseEdgeKey -fuzztime=10s -coverprofile=$(COVER_DIR)/fuzz_edgekey.out -covermode=atomic ./internal/storage/schema/
	$(GO) test -fuzz=FuzzParseNodeKey -fuzztime=10s -coverprofile=$(COVER_DIR)/fuzz_nodekey.out -covermode=atomic ./internal/storage/schema/
	$(GO) test -fuzz=FuzzConfigLoad -fuzztime=10s -coverprofile=$(COVER_DIR)/fuzz_config.out -covermode=atomic ./pkg/config/
	$(GO) test -fuzz=FuzzMatchTaint -fuzztime=10s -coverprofile=$(COVER_DIR)/fuzz_taint.out -covermode=atomic ./internal/engine/taint/
	$(GO) test -fuzz=FuzzParseQuery -fuzztime=10s -coverprofile=$(COVER_DIR)/fuzz_query.out -covermode=atomic ./internal/engine/query/
	$(GO) test -fuzz=FuzzHashHex -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_forensic.out -covermode=atomic ./internal/engine/forensic/
	$(GO) test -fuzz=FuzzAnonymizeHashString -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_anonymize.out -covermode=atomic ./pkg/anonymize/
	$(GO) test -fuzz=FuzzEventTypeString -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_syscall.out -covermode=atomic ./internal/engine/syscall/

fuzz:
	@mkdir -p $(COVER_DIR)
	$(GO) test -fuzz=FuzzParseRawEvent -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_event.out -covermode=atomic ./internal/engine/collector/
	$(GO) test -fuzz=FuzzParseEdgeKey -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_edgekey.out -covermode=atomic ./internal/storage/schema/
	$(GO) test -fuzz=FuzzParseNodeKey -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_nodekey.out -covermode=atomic ./internal/storage/schema/
	$(GO) test -fuzz=FuzzConfigLoad -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_config.out -covermode=atomic ./pkg/config/
	$(GO) test -fuzz=FuzzMatchTaint -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_taint.out -covermode=atomic ./internal/engine/taint/
	$(GO) test -fuzz=FuzzParseQuery -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_query.out -covermode=atomic ./internal/engine/query/
	$(GO) test -fuzz=FuzzHashHex -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_forensic.out -covermode=atomic ./internal/engine/forensic/
	$(GO) test -fuzz=FuzzAnonymizeHashString -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_anonymize.out -covermode=atomic ./pkg/anonymize/
	$(GO) test -fuzz=FuzzEventTypeString -fuzztime=$(FUZZ_TIME) -coverprofile=$(COVER_DIR)/fuzz_syscall.out -covermode=atomic ./internal/engine/syscall/

ext-test:
	@mkdir -p $(COVER_DIR)
	$(GO) test -v -count=1 -coverprofile=$(COVER_DIR)/ext.out -covermode=atomic ./internal/engine/edgereduce/... ./internal/engine/graphquery/... ./internal/engine/profile/... ./internal/engine/ratelimit/... ./internal/storage/schema/... ./internal/storage/pebblestore/... ./internal/storage/grpcexport/... ./internal/policy/rulescanner/... ./internal/policy/selfheal/...

cluster-test:
	@mkdir -p $(COVER_DIR)
	$(GO) test -v -count=1 -coverprofile=$(COVER_DIR)/cluster.out -covermode=atomic ./internal/stitcher/... ./internal/policy/blastradius/... ./internal/policy/deception/... ./internal/policy/supplychain/... ./internal/engine/ja3/... ./internal/engine/memforensic/... ./internal/storage/graphdb/...

graphsketch-test:
	@mkdir -p $(COVER_DIR)
	$(GO) test -v -count=1 -coverprofile=$(COVER_DIR)/graphsketch.out -covermode=atomic ./internal/stitcher/graphsketch/...

deception-test:
	@mkdir -p $(COVER_DIR)
	$(GO) test -v -count=1 -coverprofile=$(COVER_DIR)/deception.out -covermode=atomic ./internal/policy/deception/...

supplychain-test:
	@mkdir -p $(COVER_DIR)
	$(GO) test -v -count=1 -coverprofile=$(COVER_DIR)/supplychain.out -covermode=atomic ./internal/policy/supplychain/...

test-e2e:
	$(GO) test -v -count=1 -tags=e2e -timeout=600s ./test/e2e/

dist-deb: build-userspace
	bash build/packages/build_deb.sh "$(VERSION)"

dist-rpm: build-userspace
	bash build/packages/build_rpm.sh "$(VERSION)"

dist-tar: build-userspace
	bash build/packages/build_tar.sh "$(VERSION)"

dist-all: build-userspace
	bash build/packages/build_all.sh all

dist: dist-all

release-commercial:
	bash scripts/release/commercial-release.sh

package-smoke-matrix:
	bash scripts/release/package-smoke-matrix.sh

create-user:
	@if ! id -u providapt &>/dev/null; then \
		echo "Creating providapt system user (UID 950)..."; \
		useradd --system --no-create-home --uid 950 --shell /usr/sbin/nologin --comment "ProvidAPT daemon user" providapt; \
	else \
		echo "User providapt already exists."; \
	fi

clean:
	rm -rf $(OUTPUT)

verify-env:
	@bash build/verify.sh

install-deps deps:
	@bash build/install_deps.sh

run: build-core
	sudo $(BIN_OUT)/providaptd -config $(CONFIG)/providapt.toml

stop:
	sudo providaptctl -stop 2>/dev/null || sudo pkill providaptd 2>/dev/null || true

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

loader-smoke:
	@bash test/integration/loader_smoke.sh

docker-build:
	docker build -t providapt:latest -f build/docker/Dockerfile.ubuntu .

docker-run: docker-build
	docker run --rm -it --privileged -v /sys/kernel/btf:/sys/kernel/btf:ro providapt:latest

help:
	@echo 'ProvidAPT Makefile'
	@echo ''
	@echo 'Build:'
	@echo '  make build-core       Build the full product (eBPF + userspace)'
	@echo '  make build-ebpf       Compile eBPF bytecode only'
	@echo '  make generate-ebpf    Compile eBPF and generate bpf2go bindings'
	@echo '  make build-userspace  Compile Go binaries only'
	@echo '  make install-local    Build and install to the local system'
	@echo '  make demo             Build collector demo'
	@echo ''
	@echo 'Test:'
	@echo '  make test-core        Run core unit tests'
	@echo '  make ext-test         Run extended engine/storage/policy tests'
	@echo '  make cluster-test     Run stitcher and cluster tests'
	@echo '  make graphsketch-test Run graph sketch tests'
	@echo '  make deception-test   Run deception tests'
	@echo '  make supplychain-test Run supply-chain tests'
	@echo '  make attack-sim       Simulate an APT attack scenario'
	@echo '  make verify-capture   Verify provenance chain capture'
	@echo '  make loader-smoke     Run Linux loader smoke test'
	@echo ''
	@echo 'Quality:'
	@echo '  make fmt              Format all Go source'
	@echo '  make fmt-check        Check formatting'
	@echo '  make vet              Run go vet'
	@echo '  make lint             Run vet and format checks'
	@echo '  make staticcheck      Run staticcheck'
	@echo '  make test-race        Run unit tests with race detection'
	@echo ''
	@echo 'Coverage:'
	@echo '  make coverage         Run tests and print coverage summary'
	@echo '  make coverage-html    Run tests and generate HTML coverage report'
	@echo ''
	@echo 'Performance & Fuzz:'
	@echo '  make bench-baseline   Run all benchmarks and record baseline'
	@echo '  make fuzz             Run fuzz tests (FUZZ_TIME=15s default)'
	@echo '  make fuzz-short       Run quick fuzz tests (10s per target)'
	@echo ''
	@echo 'Aliases:'
	@echo '  make build            = make build-core'
	@echo '  make install          = make install-local'
	@echo '  make test             = make test-core'
	@echo ''
	@echo 'System:'
	@echo '  make verify-env       Check kernel config and dependencies'
	@echo '  make install-deps     Install build dependencies'
	@echo '  make deploy-prod      Run the production deployment helper'
	@echo ''
	@echo 'Distribution:'
	@echo '  make dist             Build all package formats (.deb/.rpm/.tar.gz)'
	@echo '  make dist-deb         Build the .deb package'
	@echo '  make dist-rpm         Build the .rpm package'
	@echo '  make dist-tar         Build the portable tarball'
	@echo '  make release-commercial Build commercial release artifacts, SBOMs, checksums, scans, and readiness report'
	@echo '  make package-smoke-matrix Test dist packages in Ubuntu/Rocky containers'
