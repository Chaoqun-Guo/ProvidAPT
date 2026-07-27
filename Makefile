.PHONY: all build build-core build-ebpf build-userspace generate-ebpf install install-local
.PHONY: clean test test-core test-race fmt fmt-check vet lint staticcheck
.PHONY: verify-env install-deps deps run stop restart deploy-prod deploy-vms verify-vm-fleet probe cgroup
.PHONY: attack-sim attack-full-chain export-ground-truth alert-quality detection-quality attack-coverage-plan model-deploy-gate verify-capture loader-smoke demo ext-test cluster-test
.PHONY: graphsketch-test deception-test supplychain-test sbom sbom-syft
.PHONY: fuzz fuzz-short coverage coverage-html bench-baseline test-e2e test-integration
.PHONY: dist dist-deb dist-rpm dist-tar dist-all release-commercial release-gates package-smoke-matrix create-user docker-build docker-run help
.PHONY: ops-secret-template ops-secret-validate ops-secret-backends ops-tls-bootstrap ops-tls-check ops-postgres-drill ops-fleet-list ops-fleet-plan ops-siem-verify ops-rbac-audit scheduled-report-plan enterprise-readiness soak-sample soak-readiness upgrade-rollout-plan onboarding-wizard plugin-release-gate

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

release-gates:
	python3 scripts/release/release_gate_status.py

package-smoke-matrix:
	bash scripts/release/package-smoke-matrix.sh

ops-secret-template:
	bash scripts/ops/render-secret-env.sh -o build/providapt.secrets.env.example

ops-secret-validate:
	@if [ -z "$(SECRET_ENV)" ]; then echo 'usage: make ops-secret-validate SECRET_ENV=/path/providapt.secrets.env'; exit 2; fi
	bash scripts/ops/validate-secret-env.sh "$(SECRET_ENV)"

ops-secret-backends:
	@if [ -z "$(SECRET_ENV)" ]; then echo 'usage: make ops-secret-backends SECRET_ENV=/path/providapt.secrets.env [OUT_DIR=build/secrets]'; exit 2; fi
	python3 scripts/ops/render-secret-backends.py --env-file "$(SECRET_ENV)" --out-dir "$(or $(OUT_DIR),build/secrets)" $(if $(INCLUDE_SECRET_VALUES),--include-values)

ops-tls-bootstrap:
	bash scripts/ops/bootstrap-tls.sh --out-dir "$(or $(TLS_OUT),build/tls)" --server-cn "$(or $(TLS_SERVER_CN),providapt-control-plane)" $(if $(TLS_SERVER_SAN),--server-san "$(TLS_SERVER_SAN)") --agent-cn "$(or $(TLS_AGENT_CNS),providapt-agent)"

ops-tls-check:
	@if [ -z "$(CERTS)" ]; then echo 'usage: make ops-tls-check CERTS="/path/server.crt /path/agent.crt"'; exit 2; fi
	bash scripts/ops/check-tls-expiry.sh $(CERTS)

ops-postgres-drill:
	@if [ -z "$(PROVIDAPT_DATABASE_DSN)" ]; then echo 'set PROVIDAPT_DATABASE_DSN before running this target'; exit 2; fi
	bash scripts/ops/postgres-drill.sh --dsn "$(PROVIDAPT_DATABASE_DSN)" --out build/postgres/providapt-control-plane.sql --report-json build/postgres/postgres-drill.json --report-md build/postgres/postgres-drill.md $(if $(PROVIDAPT_RESTORE_DSN),--restore-dsn "$(PROVIDAPT_RESTORE_DSN)")

ops-fleet-list:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'set PROVIDAPT_SERVER_URL, for example http://localhost:18080'; exit 2; fi
	bash scripts/ops/fleet-lifecycle.sh --server "$(PROVIDAPT_SERVER_URL)" list

ops-fleet-plan:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'set PROVIDAPT_SERVER_URL, for example http://localhost:18080'; exit 2; fi
	@if [ -z "$(FLEET_OPERATION)" ]; then echo 'set FLEET_OPERATION=cert-rotation|decommission|quarantine'; exit 2; fi
	bash scripts/ops/fleet-lifecycle.sh --server "$(PROVIDAPT_SERVER_URL)" plan --operation "$(FLEET_OPERATION)" $(if $(FLEET_AGENTS),--agent "$(FLEET_AGENTS)") $(if $(FLEET_GROUP),--group "$(FLEET_GROUP)") $(if $(FLEET_TAG),--tag "$(FLEET_TAG)") --out-json build/fleet/fleet-$(FLEET_OPERATION)-plan.json --out-md build/fleet/fleet-$(FLEET_OPERATION)-plan.md

ops-siem-verify:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'set PROVIDAPT_SERVER_URL, for example http://localhost:18080'; exit 2; fi
	python3 scripts/ops/verify-siem-delivery.py --server "$(PROVIDAPT_SERVER_URL)" $(if $(PROVIDAPT_API_KEY),--api-key "$(PROVIDAPT_API_KEY)") $(if $(PROVIDAPT_REQUIRE_SIEM_FORWARDED),--require-forwarded)

ops-rbac-audit:
	@if [ -z "$(PROVIDAPT_CONFIG)" ]; then echo 'usage: make ops-rbac-audit PROVIDAPT_CONFIG=/etc/providapt/providapt.toml [OUT_DIR=build/rbac]'; exit 2; fi
	python3 scripts/ops/rbac-audit.py --config "$(PROVIDAPT_CONFIG)" --out-json "$(or $(OUT_DIR),build/rbac)/rbac-audit.json" --out-md "$(or $(OUT_DIR),build/rbac)/rbac-audit.md"

scheduled-report-plan:
	python3 scripts/ops/scheduled-report-plan.py --name "$(or $(REPORT_NAME),compliance)" --cadence "$(or $(REPORT_CADENCE),1w)" --formats "$(or $(REPORT_FORMATS),markdown,json)" --recipients "$(or $(REPORT_RECIPIENTS),)" --out-dir "$(or $(REPORT_OUT_DIR),/var/lib/providapt/reports)" --retention-days "$(or $(REPORT_RETENTION_DAYS),90)" --max-report-mb "$(or $(REPORT_MAX_MB),128)" --out-json "$(or $(OUT_DIR),build/reports)/scheduled-report-plan.json" --out-md "$(or $(OUT_DIR),build/reports)/scheduled-report-plan.md"

enterprise-readiness:
	python3 scripts/ops/enterprise-readiness-report.py --release-gates "$(or $(RELEASE_GATES_JSON),build/release-gate-status.json)" --secret-manifest "$(or $(SECRET_MANIFEST),build/secrets/secret-backend-manifest.json)" --postgres-drill "$(or $(POSTGRES_DRILL_JSON),build/postgres/postgres-drill.json)" --detection-quality "$(or $(DETECTION_QUALITY_JSON),build/evaluation/detection-quality.json)" --rbac-audit "$(or $(RBAC_AUDIT_JSON),build/rbac/rbac-audit.json)" --report-plan "$(or $(REPORT_PLAN_JSON),build/reports/scheduled-report-plan.json)" --out-json "$(or $(OUT_DIR),build)/enterprise-readiness.json" --out-md "$(or $(OUT_DIR),build)/enterprise-readiness.md"

soak-sample:
	@if [ -z "$(STATUS_URL)" ] && [ -z "$(STATUS_JSON)" ]; then echo 'usage: make soak-sample STATUS_URL=http://localhost:18080/api/v1/status [SOAK_STARTED_AT_EPOCH=...] [OUT=build/performance/soak-samples.json]'; exit 2; fi
	python3 scripts/ops/collect-soak-sample.py $(if $(STATUS_URL),--status-url "$(STATUS_URL)") $(if $(STATUS_JSON),--status-json "$(STATUS_JSON)") $(if $(PROVIDAPT_API_KEY),--api-key "$(PROVIDAPT_API_KEY)") $(if $(SOAK_HOST),--host "$(SOAK_HOST)") $(if $(SOAK_STARTED_AT_EPOCH),--started-at-epoch "$(SOAK_STARTED_AT_EPOCH)") --out "$(or $(OUT),build/performance/soak-samples.json)"

soak-readiness:
	@if [ -z "$(SOAK_SAMPLES)" ]; then echo 'usage: make soak-readiness SOAK_SAMPLES=build/performance/soak-samples.json [OUT_DIR=build/performance]'; exit 2; fi
	python3 scripts/ops/soak-readiness-report.py --samples "$(SOAK_SAMPLES)" --min-hours "$(or $(SOAK_MIN_HOURS),24)" --max-cpu-percent "$(or $(SOAK_MAX_CPU_PERCENT),25)" --max-memory-mb "$(or $(SOAK_MAX_MEMORY_MB),512)" --max-disk-mb "$(or $(SOAK_MAX_DISK_MB),4096)" --max-dropped-events "$(or $(SOAK_MAX_DROPPED_EVENTS),0)" --out-json "$(or $(OUT_DIR),build/performance)/soak-readiness.json" --out-md "$(or $(OUT_DIR),build/performance)/soak-readiness.md"

upgrade-rollout-plan:
	@if [ -z "$(FLEET_JSON)" ] || [ -z "$(TARGET_VERSION)" ]; then echo 'usage: make upgrade-rollout-plan FLEET_JSON=build/fleet/fleet.json TARGET_VERSION=v1.2.3 [OUT_DIR=build/upgrade]'; exit 2; fi
	python3 scripts/upgrade/rollout-plan.py --fleet "$(FLEET_JSON)" --target-version "$(TARGET_VERSION)" $(if $(PACKAGE_PATH),--package-path "$(PACKAGE_PATH)") $(if $(EXPECTED_SHA256),--expected-sha256 "$(EXPECTED_SHA256)") $(if $(SIGNATURE_PATH),--signature-path "$(SIGNATURE_PATH)") --canary-percent "$(or $(CANARY_PERCENT),10)" --max-batch-size "$(or $(MAX_BATCH_SIZE),25)" --out-json "$(or $(OUT_DIR),build/upgrade)/rollout-plan.json" --out-md "$(or $(OUT_DIR),build/upgrade)/rollout-plan.md"

onboarding-wizard:
	python3 scripts/ops/onboarding-wizard.py --out-dir "$(or $(OUT_DIR),build/onboarding)" --mode "$(or $(ONBOARDING_MODE),standalone)" --rest-port "$(or $(REST_PORT),18080)" --grpc-port "$(or $(GRPC_PORT),50051)" $(if $(POSTGRES_DSN),--postgres-dsn "$(POSTGRES_DSN)")

plugin-release-gate:
	@if [ -z "$(PLUGIN_MANIFEST)" ]; then echo 'usage: make plugin-release-gate PLUGIN_MANIFEST=path/plugin.json [PLUGIN_SIGNATURE=path/plugin.json.sig]'; exit 2; fi
	python3 scripts/ops/plugin-release-gate.py --manifest "$(PLUGIN_MANIFEST)" $(if $(PLUGIN_SIGNATURE),--signature "$(PLUGIN_SIGNATURE)") $(if $(ALLOW_UNSIGNED_PLUGIN),--allow-unsigned) --out-json "$(or $(OUT_DIR),build/plugins)/plugin-release-gate.json" --out-md "$(or $(OUT_DIR),build/plugins)/plugin-release-gate.md"

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

deploy-vms:
	@if [ -z "$(PROVIDAPT_VM_HOSTS)" ]; then echo 'usage: make deploy-vms PROVIDAPT_VM_HOSTS="ubuntu@192.168.150.129 centos@192.168.150.131 ubuntu@192.168.150.132" [PROVIDAPT_BIN=build/bin/providaptd]'; exit 2; fi
	bash scripts/deploy/deploy-vms.sh

verify-vm-fleet:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'usage: make verify-vm-fleet PROVIDAPT_SERVER_URL=http://192.168.150.132:18080 [EXPECTED_COMMIT=...]'; exit 2; fi
	python3 scripts/deploy/verify-vm-fleet.py --server "$(PROVIDAPT_SERVER_URL)" $(if $(PROVIDAPT_API_KEY),--api-key "$(PROVIDAPT_API_KEY)") --min-agents "$(or $(MIN_AGENTS),3)" --min-healthy "$(or $(MIN_HEALTHY),3)" --max-report-age-seconds "$(or $(MAX_REPORT_AGE_SECONDS),30)" $(if $(EXPECTED_COMMIT),--expected-commit "$(EXPECTED_COMMIT)") --out-json "$(or $(OUT_DIR),build/deploy)/vm-fleet-verification.json" --out-md "$(or $(OUT_DIR),build/deploy)/vm-fleet-verification.md"

probe:
	@bash build/kernel_probe.sh

cgroup:
	@sudo bash build/setup_cgroup.sh

attack-sim:
	@bash test/integration/attack-scenarios/attack_sim.sh

attack-full-chain:
	@bash test/integration/attack-scenarios/attack_full_chain.sh

export-ground-truth:
	@if [ -z "$(GROUND_TRUTH)" ]; then echo 'usage: make export-ground-truth GROUND_TRUTH=/var/log/providapt/ground-truth [OUT_DIR=build/evaluation-dataset]'; exit 2; fi
	python3 scripts/evaluation/export_ground_truth_dataset.py "$(GROUND_TRUTH)" --out-dir "$(or $(OUT_DIR),build/evaluation-dataset)" $(if $(CORRELATION_JSON),--correlation-json "$(CORRELATION_JSON)") $(if $(DATASET_VERSION),--dataset-version "$(DATASET_VERSION)")

alert-quality:
	@if [ -z "$(ALERTS)" ]; then echo 'usage: make alert-quality ALERTS=/var/log/providapt/alerts.ndjson [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/alert_quality_report.py "$(ALERTS)" --out-json "$(or $(OUT_DIR),build/evaluation)/alert-quality.json" --out-md "$(or $(OUT_DIR),build/evaluation)/alert-quality.md"

detection-quality:
	@if [ -z "$(COVERAGE_JSON)" ] || [ -z "$(ALERT_QUALITY_JSON)" ]; then echo 'usage: make detection-quality COVERAGE_JSON=build/evaluation-dataset/coverage.json ALERT_QUALITY_JSON=build/evaluation/alert-quality.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/detection_quality_report.py --coverage "$(COVERAGE_JSON)" --alert-quality "$(ALERT_QUALITY_JSON)" --out-json "$(or $(OUT_DIR),build/evaluation)/detection-quality.json" --out-md "$(or $(OUT_DIR),build/evaluation)/detection-quality.md"

attack-coverage-plan:
	@if [ -z "$(DETECTION_QUALITY_JSON)" ]; then echo 'usage: make attack-coverage-plan DETECTION_QUALITY_JSON=build/evaluation/detection-quality.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/attack_coverage_plan.py --detection-quality "$(DETECTION_QUALITY_JSON)" --out-json "$(or $(OUT_DIR),build/evaluation)/attack-coverage-plan.json" --out-md "$(or $(OUT_DIR),build/evaluation)/attack-coverage-plan.md"

model-register:
	@if [ -z "$(DATASET_MANIFEST)" ] || [ -z "$(MODEL_NAME)" ] || [ -z "$(MODEL_VERSION)" ]; then echo 'usage: make model-register DATASET_MANIFEST=build/evaluation-dataset/manifest.json MODEL_NAME=detector MODEL_VERSION=1.0.0 [MODEL_METRICS=metrics.json] [MODEL_REGISTRY=build/model-registry.json]'; exit 2; fi
	python3 scripts/evaluation/model_registry.py register --manifest "$(DATASET_MANIFEST)" --registry "$(or $(MODEL_REGISTRY),build/model-registry.json)" --model-name "$(MODEL_NAME)" --model-version "$(MODEL_VERSION)" $(if $(MODEL_METRICS),--metrics "$(MODEL_METRICS)") $(if $(FEATURE_SCHEMA),--feature-schema "$(FEATURE_SCHEMA)") $(if $(COMMIT),--commit "$(COMMIT)") $(if $(NOTES),--notes "$(NOTES)")

model-drift:
	@if [ -z "$(BASELINE_MANIFEST)" ] || [ -z "$(CANDIDATE_MANIFEST)" ]; then echo 'usage: make model-drift BASELINE_MANIFEST=old/manifest.json CANDIDATE_MANIFEST=new/manifest.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/model_registry.py drift --baseline "$(BASELINE_MANIFEST)" --candidate "$(CANDIDATE_MANIFEST)" --threshold-percent "$(or $(DRIFT_THRESHOLD_PERCENT),20)" --out-json "$(or $(OUT_DIR),build/evaluation)/model-drift.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-drift.md"

model-feature-schema:
	python3 scripts/evaluation/model_registry.py export-schema --version "$(or $(FEATURE_SCHEMA_VERSION),1)" --out "$(or $(OUT_DIR),build/evaluation)/model-feature-schema.json"

model-feature-schema-check:
	@if [ -z "$(FEATURE_SCHEMA)" ]; then echo 'usage: make model-feature-schema-check FEATURE_SCHEMA=build/evaluation/model-feature-schema.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/model_registry.py validate-schema --schema-file "$(FEATURE_SCHEMA)" --out "$(or $(OUT_DIR),build/evaluation)/model-feature-schema-check.json" --strict

model-deploy-gate:
	@if [ -z "$(MODEL_REGISTRY)" ] || [ -z "$(MODEL_NAME)" ] || [ -z "$(MODEL_VERSION)" ]; then echo 'usage: make model-deploy-gate MODEL_REGISTRY=build/model-registry.json MODEL_NAME=detector MODEL_VERSION=1.0.0'; exit 2; fi
	python3 scripts/evaluation/model_deploy_gate.py --registry "$(MODEL_REGISTRY)" --model-name "$(MODEL_NAME)" --model-version "$(MODEL_VERSION)" $(if $(DETECTION_QUALITY_JSON),--detection-quality "$(DETECTION_QUALITY_JSON)") $(if $(MODEL_DRIFT_JSON),--drift-report "$(MODEL_DRIFT_JSON)") $(if $(FEATURE_SCHEMA_CHECK_JSON),--feature-schema-check "$(FEATURE_SCHEMA_CHECK_JSON)") --min-precision "$(or $(MIN_PRECISION),70)" --min-recall "$(or $(MIN_RECALL),80)" --out-json "$(or $(OUT_DIR),build/evaluation)/model-deploy-gate.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-deploy-gate.md"

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
	@echo '  make attack-full-chain Run ATT&CK full-chain simulation'
	@echo '  make export-ground-truth Export train/test labels and ATT&CK coverage'
	@echo '  make alert-quality    Export annotated alert precision and review metrics'
	@echo '  make detection-quality Merge coverage and alert quality into precision/recall/F1'
	@echo '  make attack-coverage-plan Plan safe simulations for missed ATT&CK techniques'
	@echo '  make model-deploy-gate MODEL_REGISTRY=... MODEL_NAME=... MODEL_VERSION=... Gate model deployment'
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
	@echo '  make deploy-vms       Deploy one checked Linux binary to constrained VMs'
	@echo '  make verify-vm-fleet  Verify control-plane dashboard, fleet, graph, and alerts'
	@echo ''
	@echo 'Distribution:'
	@echo '  make dist             Build all package formats (.deb/.rpm/.tar.gz)'
	@echo '  make dist-deb         Build the .deb package'
	@echo '  make dist-rpm         Build the .rpm package'
	@echo '  make dist-tar         Build the portable tarball'
	@echo '  make release-commercial Build commercial release artifacts, SBOMs, checksums, scans, and readiness report'
	@echo '  make release-gates     Collect CI, scanner, approval, and artifact gate status'
	@echo '  make package-smoke-matrix Test dist packages in Ubuntu/Rocky containers'
	@echo ''
	@echo 'Operations:'
	@echo '  make ops-secret-template Generate production secret env template'
	@echo '  make ops-secret-validate SECRET_ENV=... Validate production secret env file'
	@echo '  make ops-tls-bootstrap TLS CA, server, and agent certificate bootstrap'
	@echo '  make ops-tls-check CERTS="..." Check TLS certificate expiry'
	@echo '  make ops-postgres-drill Run PostgreSQL backup/restore drill'
	@echo '  make ops-fleet-list List control-plane fleet state'
	@echo '  make ops-fleet-plan FLEET_OPERATION=... Generate fleet lifecycle plan'
	@echo '  make ops-siem-verify Queue and verify SIEM test delivery'
	@echo '  make ops-rbac-audit PROVIDAPT_CONFIG=... Audit RBAC and tenant scoping'
	@echo '  make scheduled-report-plan Generate executive/compliance report schedule'
	@echo '  make enterprise-readiness Aggregate release, secret, PostgreSQL, and detection evidence'
	@echo '  make soak-sample STATUS_URL=... Append one long-duration soak sample'
	@echo '  make soak-readiness SOAK_SAMPLES=... Check long-duration performance budgets'
	@echo '  make upgrade-rollout-plan FLEET_JSON=... TARGET_VERSION=... Plan staged upgrades'
	@echo '  make onboarding-wizard Generate first-run config and checklist'
	@echo '  make plugin-release-gate PLUGIN_MANIFEST=... Validate plugin signing and compatibility'
