.PHONY: all build build-core build-ebpf build-userspace generate-ebpf install install-local
.PHONY: clean test test-core test-race fmt fmt-check vet lint staticcheck
.PHONY: verify-env install-deps deps run stop restart deploy-prod deploy-vms verify-vm-fleet verify-vm-open-source-residue verify-vm-config probe cgroup
.PHONY: attack-sim attack-full-chain export-ground-truth graph-dataset dataset-split-gate graph-augment graph-train ml-training-pipeline ml-readiness-gate alert-quality detection-quality attack-coverage-plan model-closed-loop model-deploy-gate model-lifecycle-gate model-lifecycle-example-gate upgrade-artifact verify-capture loader-smoke demo ext-test cluster-test
.PHONY: graphsketch-test deception-test supplychain-test sbom sbom-syft
.PHONY: fuzz fuzz-short coverage coverage-html bench-baseline test-e2e test-integration
.PHONY: dist dist-deb dist-rpm dist-tar dist-all release-open-source github-actions-evidence release-gates release-security-local-gate security-scan-manifest artifact-signing-gate release-evidence-consistency-gate operator-release-gate release-blocker-backlog open-source-readiness-backlog open-source-development-backlog open-source-milestone open-source-evidence-summary open-source-local-closure package-smoke-matrix create-user docker-build docker-run help
.PHONY: ops-secret-template ops-secret-validate ops-secret-backends ops-tls-bootstrap ops-tls-check ops-postgres-drill ops-fleet-list ops-fleet-action ops-fleet-plan ops-siem-verify ops-rbac-audit policy-approval-gate backup-readiness-gate support-bundle-gate deployment-diagnostics-gate install-delivery-check observability-pack-check visual-regression-snapshots visual-regression-gate trace-svg-stress trace-svg-stress-example capture-enrichment-field-gate collect-vm-capture-evidence security-hardening-gate scheduled-report-plan open-source-operations production-readiness-gate operations-readiness-gate operator-env-certification-gate open-source-readiness-gate soak-sample soak-readiness upgrade-rollout-plan onboarding-wizard onboarding-example-gate plugin-release-gate plugin-catalog-gate plugin-example-gates rbac-hardening-example-gate

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
TAILSCALE_DOMAIN ?= ts.net.example
VM_CONTROL_HOST ?= vm-ubuntu-master.$(TAILSCALE_DOMAIN)
PROVIDAPT_VM_HOSTS ?= ubuntu@vm-ubuntu-slave.$(TAILSCALE_DOMAIN) centos@vm-centos-slave.$(TAILSCALE_DOMAIN) ubuntu@$(VM_CONTROL_HOST)
PROVIDAPT_SERVER_URL ?= http://$(VM_CONTROL_HOST):18080

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

release-open-source:
	bash scripts/release/open-source-release.sh

github-actions-evidence:
	python3 scripts/release/github-actions-evidence.py --repo . --limit "$(or $(CI_RUN_LIMIT),20)" --out-json "$(or $(OUT_DIR),build/ci)/github-actions-evidence.json" --out-md "$(or $(OUT_DIR),build/ci)/github-actions-evidence.md" $(if $(RELEASE_EVIDENCE),--release-evidence "$(RELEASE_EVIDENCE)")

release-gates:
	python3 scripts/release/release_gate_status.py $(if $(SKIP_CI),--skip-ci) $(if $(RELEASE_WAIVER),--waiver "$(RELEASE_WAIVER)") $(if $(CI_EVIDENCE),--ci-evidence "$(CI_EVIDENCE)")

release-security-local-gate:
	python3 scripts/release/release-security-local-gate.py --project-dir . --security-dir "$(or $(SECURITY_DIR),build/security)" $(if $(VERSION),--version "$(VERSION)") $(if $(COMMIT),--commit "$(COMMIT)") $(if $(FULL_COMMIT),--full-commit "$(FULL_COMMIT)") $(if $(GO_TAGS),--go-tags "$(GO_TAGS)") $(if $(SCAN_TIMEOUT),--timeout "$(SCAN_TIMEOUT)") $(if $(SKIP_GOVULNCHECK),--skip-govulncheck) $(if $(SKIP_GRYPE),--skip-grype) $(if $(SKIP_TRIVY),--skip-trivy) $(if $(ALLOW_PARTIAL),--allow-partial) --out-json "$(or $(OUT_DIR),build/security)/release-security-local-gate.json" --out-md "$(or $(OUT_DIR),build/security)/release-security-local-gate.md"

security-scan-manifest:
	python3 scripts/release/security-scan-manifest.py --security-dir "$(or $(SECURITY_DIR),build/security)" $(if $(VERSION),--version "$(VERSION)") $(if $(COMMIT),--commit "$(COMMIT)") $(if $(FULL_COMMIT),--full-commit "$(FULL_COMMIT)") $(if $(ALLOW_PARTIAL),--allow-partial) --out-json "$(or $(OUT_DIR),build/security)/scan-manifest.json" --out-md "$(or $(OUT_DIR),build/security)/scan-manifest.md"

artifact-signing-gate:
	python3 scripts/release/artifact-signing-gate.py --dist-dir "$(or $(DIST_DIR),dist)" --checksums "$(or $(CHECKSUMS),$(or $(DIST_DIR),dist)/checksums.txt)" --signature "$(or $(SIGNATURE),$(or $(DIST_DIR),dist)/checksums.txt.sig)" $(foreach artifact,$(REQUIRED_ARTIFACTS),--required-artifact "$(artifact)") --out-json "$(or $(OUT_DIR),build/artifact-signing)/artifact-signing-gate.json" --out-md "$(or $(OUT_DIR),build/artifact-signing)/artifact-signing-gate.md"

release-evidence-consistency-gate:
	python3 scripts/release/release-evidence-consistency-gate.py --dist-dir "$(or $(DIST_DIR),dist)" --release-readiness "$(or $(RELEASE_READINESS),$(or $(DIST_DIR),dist)/release-readiness.md)" --scan-manifest "$(or $(SCAN_MANIFEST),build/security/scan-manifest.json)" --artifact-signing-gate "$(or $(ARTIFACT_SIGNING_GATE),build/artifact-signing/artifact-signing-gate.json)" $(if $(VERSION),--version "$(VERSION)") $(if $(COMMIT),--commit "$(COMMIT)") $(if $(FULL_COMMIT),--full-commit "$(FULL_COMMIT)") --out-json "$(or $(OUT_DIR),build/release-evidence)/release-evidence-consistency-gate.json" --out-md "$(or $(OUT_DIR),build/release-evidence)/release-evidence-consistency-gate.md"

operator-release-gate:
	python3 scripts/release/operator-release-gate.py --release-gates "$(or $(RELEASE_GATES_JSON),build/release-gate-status.json)" --dist-dir "$(or $(DIST_DIR),dist)" --artifact-signing-gate "$(or $(ARTIFACT_SIGNING_GATE),build/artifact-signing/artifact-signing-gate.json)" --release-evidence-consistency-gate "$(or $(RELEASE_EVIDENCE_CONSISTENCY_GATE),build/release-evidence/release-evidence-consistency-gate.json)" --package-smoke-dir "$(or $(PACKAGE_SMOKE_DIR),build/package-smoke)" --production-readiness-gate "$(or $(PRODUCTION_READINESS_GATE),build/production-readiness/production-readiness-gate.json)" --ml-readiness-gate "$(or $(ML_READINESS_GATE),build/ml-readiness/ml-readiness-gate.json)" --operations-readiness-gate "$(or $(OPERATIONS_READINESS_GATE),build/operations-readiness/operations-readiness-gate.json)" --open-source-readiness-gate "$(or $(OPEN_SOURCE_READINESS_GATE),build/open-source-readiness/open-source-readiness-gate.json)" $(if $(ALLOW_SKIPPED_CI),--allow-skipped-ci) --out-json "$(or $(OUT_DIR),build/operator-release)/operator-release-gate.json" --out-md "$(or $(OUT_DIR),build/operator-release)/operator-release-gate.md"

release-blocker-backlog:
	python3 scripts/release/release-blocker-backlog.py --operator-release-gate "$(or $(OPERATOR_RELEASE_GATE),build/operator-release/operator-release-gate.json)" --out-json "$(or $(OUT_DIR),build/operator-release)/release-blocker-backlog.json" --out-md "$(or $(OUT_DIR),build/operator-release)/release-blocker-backlog.md"

open-source-readiness-backlog:
	python3 scripts/release/release-blocker-backlog.py --source-report "$(or $(OPEN_SOURCE_READINESS_GATE),build/open-source-readiness/open-source-readiness-gate.json)" --source-label open-source-readiness --out-json "$(or $(OUT_DIR),build/open-source-readiness)/open-source-readiness-backlog.json" --out-md "$(or $(OUT_DIR),build/open-source-readiness)/open-source-readiness-backlog.md"

open-source-development-backlog:
	python3 scripts/release/open-source-development-backlog.py $(if $(LOCAL_ONLY),--local-only) $(if $(PHASE),--phase "$(PHASE)") $(if $(GITHUB_ACTIONS_EVIDENCE),--github-actions-evidence "$(GITHUB_ACTIONS_EVIDENCE)") $(if $(RELEASE_GATES_JSON),--release-gates "$(RELEASE_GATES_JSON)") $(if $(RELEASE_EVIDENCE_CONSISTENCY_GATE),--release-evidence-consistency-gate "$(RELEASE_EVIDENCE_CONSISTENCY_GATE)") $(if $(ARTIFACT_SIGNING_GATE),--artifact-signing-gate "$(ARTIFACT_SIGNING_GATE)") $(if $(OPERATOR_RELEASE_GATE),--operator-release-gate "$(OPERATOR_RELEASE_GATE)") $(if $(VISUAL_REGRESSION_GATE),--visual-regression-gate "$(VISUAL_REGRESSION_GATE)") $(if $(TRACE_SVG_STRESS),--trace-svg-stress "$(TRACE_SVG_STRESS)") $(if $(CAPTURE_ENRICHMENT_GATE),--capture-enrichment-gate "$(CAPTURE_ENRICHMENT_GATE)") $(if $(MODEL_LIFECYCLE_GATE),--model-lifecycle-gate "$(MODEL_LIFECYCLE_GATE)") $(if $(SIEM_VERIFY),--siem-verify "$(SIEM_VERIFY)") $(if $(RBAC_AUDIT),--rbac-audit "$(RBAC_AUDIT)") $(if $(POLICY_APPROVAL_GATE),--policy-approval-gate "$(POLICY_APPROVAL_GATE)") $(if $(SOAK_READINESS),--soak-readiness "$(SOAK_READINESS)") $(if $(OPERATOR_ENV_CERTIFICATION_GATE),--operator-env-certification-gate "$(OPERATOR_ENV_CERTIFICATION_GATE)") $(if $(PLUGIN_CATALOG_GATE),--plugin-catalog-gate "$(PLUGIN_CATALOG_GATE)") $(if $(ONBOARDING_MANIFEST),--onboarding-manifest "$(ONBOARDING_MANIFEST)") $(if $(EXTERNAL_APPROVAL),--external-approval "$(EXTERNAL_APPROVAL)") --out-json "$(or $(OUT_DIR),build/open-source-readiness)/open-source-development-backlog.json" --out-md "$(or $(OUT_DIR),build/open-source-readiness)/open-source-development-backlog.md"

open-source-milestone:
	python3 scripts/release/open-source-milestone.py --open-source-readiness-gate "$(or $(OPEN_SOURCE_READINESS_GATE),build/open-source-readiness/open-source-readiness-gate.json)" --open-source-readiness-backlog "$(or $(OPEN_SOURCE_READINESS_BACKLOG),build/open-source-readiness/open-source-readiness-backlog.json)" --open-source-development-backlog "$(or $(OPEN_SOURCE_DEVELOPMENT_BACKLOG),build/open-source-readiness/open-source-development-backlog.json)" --release-gates "$(or $(RELEASE_GATES_JSON),build/release-gate-status.json)" --release-evidence-consistency-gate "$(or $(RELEASE_EVIDENCE_CONSISTENCY_GATE),build/release-evidence/release-evidence-consistency-gate.json)" --model-lifecycle-gate "$(or $(MODEL_LIFECYCLE_GATE),build/evaluation/model-lifecycle-gate.json)" --visual-regression-snapshots "$(or $(VISUAL_REGRESSION_SNAPSHOTS),build/visual-regression/visual-regression-snapshots.json)" --trace-svg-stress "$(or $(TRACE_SVG_STRESS),build/trace-stress/trace-svg-stress.json)" --onboarding-manifest "$(or $(ONBOARDING_MANIFEST),build/onboarding/onboarding-manifest.json)" $(if $(ALLOW_MISSING),--allow-missing) --out-json "$(or $(OUT_DIR),build/open-source-readiness)/open-source-milestone.json" --out-md "$(or $(OUT_DIR),build/open-source-readiness)/open-source-milestone.md"

open-source-evidence-summary:
	python3 scripts/release/open-source-evidence-summary.py --open-source-milestone "$(or $(OPEN_SOURCE_MILESTONE),build/open-source-readiness/open-source-milestone.json)" --open-source-readiness-backlog "$(or $(OPEN_SOURCE_READINESS_BACKLOG),build/open-source-readiness/open-source-readiness-backlog.json)" --visual-regression-gate "$(or $(VISUAL_REGRESSION_GATE),build/visual-regression/visual-regression-gate.json)" --trace-svg-stress "$(or $(TRACE_SVG_STRESS),build/trace-stress/trace-svg-stress.json)" --onboarding-manifest "$(or $(ONBOARDING_MANIFEST),build/onboarding/onboarding-manifest.json)" --model-lifecycle-gate "$(or $(MODEL_LIFECYCLE_GATE),build/evaluation/model-lifecycle-gate.json)" $(if $(ALLOW_MISSING),--allow-missing) --out-json "$(or $(OUT_DIR),build/open-source-readiness)/open-source-evidence-summary.json" --out-md "$(or $(OUT_DIR),build/open-source-readiness)/open-source-evidence-summary.md"

open-source-local-closure:
	python3 scripts/release/open-source-local-closure.py $(if $(PROVIDAPT_SERVER_URL),--server-url "$(PROVIDAPT_SERVER_URL)") $(if $(ALERT_IDS),--alert-ids "$(ALERT_IDS)") $(if $(RELEASE_TAG),--release-tag "$(RELEASE_TAG)") $(if $(SIGNATURE),--signature "$(SIGNATURE)") $(if $(MODEL_CLOSED_LOOP_JSON),--model-closed-loop "$(MODEL_CLOSED_LOOP_JSON)") $(if $(MODEL_DEPLOY_GATE_JSON),--model-deploy-gate "$(MODEL_DEPLOY_GATE_JSON)") $(if $(MODEL_DRIFT_JSON),--model-drift "$(MODEL_DRIFT_JSON)") $(if $(MODEL_APPROVAL),--model-approval "$(MODEL_APPROVAL)") $(if $(PROVIDAPT_CONFIG),--providapt-config "$(PROVIDAPT_CONFIG)") $(if $(RBAC_AUDIT),--rbac-audit "$(RBAC_AUDIT)") $(if $(POLICY_APPROVAL_GATE),--policy-approval-gate "$(POLICY_APPROVAL_GATE)") $(if $(AUDIT_EXPORT),--audit-export "$(AUDIT_EXPORT)") $(if $(ROLE_REVIEW),--role-review "$(ROLE_REVIEW)") $(if $(PLUGIN_MANIFEST),--plugin-manifest "$(PLUGIN_MANIFEST)") $(if $(PLUGIN_SIGNATURE),--plugin-signature "$(PLUGIN_SIGNATURE)") $(if $(PLUGIN_GATES),--plugin-gates "$(PLUGIN_GATES)") --out-json "$(or $(OUT_DIR),build/open-source-readiness)/open-source-local-closure.json" --out-md "$(or $(OUT_DIR),build/open-source-readiness)/open-source-local-closure.md"

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

ops-fleet-action:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'set PROVIDAPT_SERVER_URL, for example http://localhost:18080'; exit 2; fi
	@if [ -z "$(FLEET_AGENTS)" ]; then echo 'set FLEET_AGENTS=agent-a,agent-b'; exit 2; fi
	@if [ -z "$(FLEET_STATE)" ]; then echo 'set FLEET_STATE=approved|quarantined|revoked'; exit 2; fi
	bash scripts/ops/fleet-lifecycle.sh --server "$(PROVIDAPT_SERVER_URL)" action --agent "$(FLEET_AGENTS)" --state "$(FLEET_STATE)" $(if $(FLEET_NOTE),--note "$(FLEET_NOTE)") --out-json build/fleet/fleet-$(FLEET_STATE)-action.json --out-md build/fleet/fleet-$(FLEET_STATE)-action.md

ops-fleet-plan:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'set PROVIDAPT_SERVER_URL, for example http://localhost:18080'; exit 2; fi
	@if [ -z "$(FLEET_OPERATION)" ]; then echo 'set FLEET_OPERATION=cert-rotation|decommission|quarantine'; exit 2; fi
	bash scripts/ops/fleet-lifecycle.sh --server "$(PROVIDAPT_SERVER_URL)" plan --operation "$(FLEET_OPERATION)" $(if $(FLEET_AGENTS),--agent "$(FLEET_AGENTS)") $(if $(FLEET_GROUP),--group "$(FLEET_GROUP)") $(if $(FLEET_TAG),--tag "$(FLEET_TAG)") --out-json build/fleet/fleet-$(FLEET_OPERATION)-plan.json --out-md build/fleet/fleet-$(FLEET_OPERATION)-plan.md

ops-siem-verify:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'set PROVIDAPT_SERVER_URL, for example http://localhost:18080'; exit 2; fi
	@python3 scripts/ops/verify-siem-delivery.py --server "$(PROVIDAPT_SERVER_URL)" $(if $(PROVIDAPT_REQUIRE_SIEM_FORWARDED),--require-forwarded)

ops-rbac-audit:
	@if [ -z "$(PROVIDAPT_CONFIG)" ]; then echo 'usage: make ops-rbac-audit PROVIDAPT_CONFIG=/etc/providapt/providapt.toml [OUT_DIR=build/rbac]'; exit 2; fi
	python3 scripts/ops/rbac-audit.py --config "$(PROVIDAPT_CONFIG)" --out-json "$(or $(OUT_DIR),build/rbac)/rbac-audit.json" --out-md "$(or $(OUT_DIR),build/rbac)/rbac-audit.md"

policy-approval-gate:
	python3 scripts/ops/policy-approval-gate.py --rbac-audit "$(or $(RBAC_AUDIT),build/rbac/rbac-audit.json)" --compliance-status "$(or $(COMPLIANCE_STATUS),build/compliance/compliance-status.json)" $(if $(AUDIT_LOG),--audit-log "$(AUDIT_LOG)") $(foreach action,$(REQUIRED_APPROVAL_ACTIONS),--required-action "$(action)") --min-tenant-scoped-keys "$(or $(MIN_TENANT_SCOPED_KEYS),1)" --min-tenants "$(or $(MIN_TENANTS),1)" $(if $(REQUIRE_APPROVAL_AUDIT),--require-audit-log) --out-json "$(or $(OUT_DIR),build/policy-approval)/policy-approval-gate.json" --out-md "$(or $(OUT_DIR),build/policy-approval)/policy-approval-gate.md"

rbac-hardening-example-gate: plugin-example-gates
	python3 scripts/ops/rbac-audit.py --config examples/rbac-hardening/providapt.toml --out-json "build/rbac/rbac-audit.json" --out-md "build/rbac/rbac-audit.md"
	python3 scripts/ops/policy-approval-gate.py --rbac-audit build/rbac/rbac-audit.json --compliance-status examples/rbac-hardening/compliance-status.json --audit-log examples/rbac-hardening/audit-log.ndjson --require-audit-log --min-tenant-scoped-keys 2 --min-tenants 2 --out-json "build/policy-approval/policy-approval-gate.json" --out-md "build/policy-approval/policy-approval-gate.md"
	python3 scripts/ops/operator-environment-certification-gate.py --rbac-audit build/rbac/rbac-audit.json --policy-approval-gate build/policy-approval/policy-approval-gate.json --audit-export examples/rbac-hardening/audit-export.csv --role-review examples/rbac-hardening/role-review.json --require-delegated-admin --require-audit-export --require-role-review --min-tenants 2 --min-tenant-scoped-keys 2 --min-audit-export-rows 1 --siem-verify examples/rbac-hardening/siem-verification.json --siem-certification examples/rbac-hardening/siem-certification.json --require-siem-certification --upgrade-rollout examples/rbac-hardening/upgrade-rollout.json --require-agent-groups --soak-readiness examples/rbac-hardening/soak-readiness.json --production-readiness-gate examples/rbac-hardening/production-readiness-gate.json --deployment-diagnostics-gate examples/rbac-hardening/deployment-diagnostics-gate.json --backup-readiness-gate examples/rbac-hardening/backup-readiness-gate.json --require-tls --require-state-backend --plugin-catalog-gate build/plugins/plugin-catalog-gate.json --require-plugin-gate --require-plugin-signature --require-plugin-permissions --onboarding-manifest examples/rbac-hardening/onboarding-manifest.json --required-onboarding-check tailscale --required-onboarding-check ssh --required-onboarding-check api --required-onboarding-check tls --out-json "build/operator-certification/operator-environment-certification-gate.json" --out-md "build/operator-certification/operator-environment-certification-gate.md"

backup-readiness-gate:
	python3 scripts/ops/backup-readiness-gate.py --backup-summary "$(or $(BACKUP_SUMMARY),build/backup/backup-summary.json)" --min-backup-bytes "$(or $(MIN_BACKUP_BYTES),1)" $(if $(REQUIRE_BACKUP_RESTORE),--require-restore) $(if $(REQUIRE_BACKUP_CUTOVER),--require-cutover) $(if $(REQUIRE_BACKUP_DOWNLOAD),--require-download) --out-json "$(or $(OUT_DIR),build/backup)/backup-readiness-gate.json" --out-md "$(or $(OUT_DIR),build/backup)/backup-readiness-gate.md"

support-bundle-gate:
	python3 scripts/ops/support-bundle-gate.py --support-summary "$(or $(SUPPORT_SUMMARY),build/support/support-bundle-summary.json)" $(if $(REQUIRE_SUPPORT_ARCHIVE),--require-archive) $(if $(REQUIRE_SUPPORT_REDACTED),--require-redacted) $(if $(REQUIRE_SUPPORT_AUDIT),--require-audit) $(if $(REQUIRE_SUPPORT_DOWNLOAD),--require-download) $(if $(CHECK_SUPPORT_FILES),--check-files) --out-json "$(or $(OUT_DIR),build/support)/support-bundle-gate.json" --out-md "$(or $(OUT_DIR),build/support)/support-bundle-gate.md"

deployment-diagnostics-gate:
	python3 scripts/ops/deployment-diagnostics-gate.py --status-json "$(or $(STATUS_JSON),build/deploy/status.json)" $(if $(REQUIRE_TLS),--require-tls) $(if $(REQUIRE_STORAGE_ENCRYPTION),--require-storage-encryption) $(if $(REQUIRE_POLICY_SYNC),--require-policy-sync) $(if $(REQUIRE_KERNEL_ATTACH),--require-kernel-attach) $(if $(REQUIRE_SUPPORT_BUNDLE),--require-support-bundle) $(if $(REQUIRE_CONTROL_PLANE),--require-control-plane) $(if $(REQUIRE_STATE_BACKEND),--require-state-backend) --out-json "$(or $(OUT_DIR),build/deploy)/deployment-diagnostics-gate.json" --out-md "$(or $(OUT_DIR),build/deploy)/deployment-diagnostics-gate.md"

install-delivery-check:
	python3 scripts/ops/install-delivery-check.py --root "." --bin-dir "$(or $(BIN_DIR),build/bin)" --config "$(or $(PROVIDAPT_CONFIG),examples/config/providapt.production.yaml)" --service "$(or $(SERVICE_FILE),deploy/linux/providapt.service)" --env-file "$(or $(ENV_FILE),deploy/linux/providapt.env)" $(if $(STRICT_BINARIES),--strict-binaries) --out-json "$(or $(OUT_DIR),build/install-delivery)/install-delivery-check.json" --out-md "$(or $(OUT_DIR),build/install-delivery)/install-delivery-check.md"

observability-pack-check:
	@python3 scripts/ops/observability-pack-check.py --prometheus "$(or $(PROMETHEUS_CONFIG),scripts/docker/prometheus.yml)" --alerts "$(or $(PROMETHEUS_ALERTS),scripts/docker/providapt_alerts.yml)" --dashboard "$(or $(GRAFANA_DASHBOARD),scripts/docker/providapt_dashboard.json)" $(if $(PROVIDAPT_SERVER_URL),--server "$(PROVIDAPT_SERVER_URL)") --out-json "$(or $(OUT_DIR),build/observability)/observability-pack-check.json" --out-md "$(or $(OUT_DIR),build/observability)/observability-pack-check.md"

security-hardening-gate:
	python3 scripts/ops/security-hardening-gate.py --config "$(or $(PROVIDAPT_CONFIG),examples/config/providapt.production.yaml)" --service "$(or $(SERVICE_FILE),deploy/linux/providapt.service)" --env-file "$(or $(ENV_FILE),deploy/linux/providapt.env)" $(if $(RBAC_AUDIT),--rbac-audit "$(RBAC_AUDIT)") $(if $(STRICT_SECURITY),--strict) --out-json "$(or $(OUT_DIR),build/security-hardening)/security-hardening-gate.json" --out-md "$(or $(OUT_DIR),build/security-hardening)/security-hardening-gate.md"

scheduled-report-plan:
	python3 scripts/ops/scheduled-report-plan.py --name "$(or $(REPORT_NAME),compliance)" --cadence "$(or $(REPORT_CADENCE),1w)" --formats "$(or $(REPORT_FORMATS),markdown,json)" --recipients "$(or $(REPORT_RECIPIENTS),)" --out-dir "$(or $(REPORT_OUT_DIR),/var/lib/providapt/reports)" --retention-days "$(or $(REPORT_RETENTION_DAYS),90)" --max-report-mb "$(or $(REPORT_MAX_MB),128)" --out-json "$(or $(OUT_DIR),build/reports)/scheduled-report-plan.json" --out-md "$(or $(OUT_DIR),build/reports)/scheduled-report-plan.md"

open-source-operations:
	python3 scripts/ops/open-source-operations-report.py --release-gates "$(or $(RELEASE_GATES_JSON),build/release-gate-status.json)" --secret-manifest "$(or $(SECRET_MANIFEST),build/secrets/secret-backend-manifest.json)" --postgres-drill "$(or $(POSTGRES_DRILL_JSON),build/postgres/postgres-drill.json)" --detection-quality "$(or $(DETECTION_QUALITY_JSON),build/evaluation/detection-quality.json)" --rbac-audit "$(or $(RBAC_AUDIT_JSON),build/rbac/rbac-audit.json)" --report-plan "$(or $(REPORT_PLAN_JSON),build/reports/scheduled-report-plan.json)" --siem-verify "$(or $(SIEM_VERIFY_JSON),build/siem/siem-verification.json)" --upgrade-rollout "$(or $(UPGRADE_ROLLOUT_JSON),build/upgrade/rollout-plan.json)" --out-json "$(or $(OUT_DIR),build)/open-source-operations.json" --out-md "$(or $(OUT_DIR),build)/open-source-operations.md"

production-readiness-gate:
	@python3 scripts/ops/production-readiness-gate.py --secret-manifest "$(or $(SECRET_MANIFEST),build/secrets/secret-backend-manifest.json)" --tls-manifest "$(or $(TLS_MANIFEST),build/tls/manifest.json)" $(if $(POSTGRES_REPORT),--postgres-report "$(POSTGRES_REPORT)") $(if $(PROVIDAPT_SERVER_URL),--server "$(PROVIDAPT_SERVER_URL)") --min-agents "$(or $(MIN_AGENTS),3)" --min-healthy "$(or $(MIN_HEALTHY),3)" --max-report-age-seconds "$(or $(MAX_REPORT_AGE_SECONDS),60)" --out-json "$(or $(OUT_DIR),build/production-readiness)/production-readiness-gate.json" --out-md "$(or $(OUT_DIR),build/production-readiness)/production-readiness-gate.md"

operations-readiness-gate:
	python3 scripts/ops/operations-readiness-gate.py --production-readiness-gate "$(or $(PRODUCTION_READINESS_GATE),build/production-readiness/production-readiness-gate.json)" --ml-readiness-gate "$(or $(ML_READINESS_GATE),build/ml-readiness/ml-readiness-gate.json)" --fleet-verification "$(or $(FLEET_VERIFICATION),build/deploy/vm-fleet-verification.json)" --soak-readiness "$(or $(SOAK_READINESS),build/performance/soak-readiness.json)" --upgrade-rollout "$(or $(UPGRADE_ROLLOUT),build/upgrade/rollout-plan.json)" --siem-verify "$(or $(SIEM_VERIFY),build/siem/siem-verification.json)" --rbac-audit "$(or $(RBAC_AUDIT),build/rbac/rbac-audit.json)" --policy-approval-gate "$(or $(POLICY_APPROVAL_GATE),build/policy-approval/policy-approval-gate.json)" --backup-readiness-gate "$(or $(BACKUP_READINESS_GATE),build/backup/backup-readiness-gate.json)" --support-bundle-gate "$(or $(SUPPORT_BUNDLE_GATE),build/support/support-bundle-gate.json)" --deployment-diagnostics-gate "$(or $(DEPLOYMENT_DIAGNOSTICS_GATE),build/deploy/deployment-diagnostics-gate.json)" --install-delivery-check "$(or $(INSTALL_DELIVERY_CHECK),build/install-delivery/install-delivery-check.json)" --observability-pack-check "$(or $(OBSERVABILITY_PACK_CHECK),build/observability/observability-pack-check.json)" --security-hardening-gate "$(or $(SECURITY_HARDENING_GATE),build/security-hardening/security-hardening-gate.json)" --visual-regression-gate "$(or $(VISUAL_REGRESSION_GATE),build/visual-regression/visual-regression-gate.json)" --capture-enrichment-gate "$(or $(CAPTURE_ENRICHMENT_GATE),build/capture-quality/capture-enrichment-field-gate.json)" --out-json "$(or $(OUT_DIR),build/operations-readiness)/operations-readiness-gate.json" --out-md "$(or $(OUT_DIR),build/operations-readiness)/operations-readiness-gate.md"

operator-env-certification-gate:
	python3 scripts/ops/operator-environment-certification-gate.py --rbac-audit "$(or $(RBAC_AUDIT),build/rbac/rbac-audit.json)" --policy-approval-gate "$(or $(POLICY_APPROVAL_GATE),build/policy-approval/policy-approval-gate.json)" $(if $(AUDIT_EXPORT),--audit-export "$(AUDIT_EXPORT)") $(if $(ROLE_REVIEW),--role-review "$(ROLE_REVIEW)") $(if $(REQUIRE_DELEGATED_ADMIN),--require-delegated-admin) $(if $(REQUIRE_AUDIT_EXPORT),--require-audit-export) $(if $(REQUIRE_ROLE_REVIEW),--require-role-review) --min-tenants "$(or $(MIN_TENANTS),1)" --min-tenant-scoped-keys "$(or $(MIN_TENANT_SCOPED_KEYS),1)" --min-audit-export-rows "$(or $(MIN_AUDIT_EXPORT_ROWS),1)" --siem-verify "$(or $(SIEM_VERIFY),build/siem/siem-verification.json)" $(if $(SIEM_CERTIFICATION),--siem-certification "$(SIEM_CERTIFICATION)") $(if $(REQUIRE_SIEM_CERTIFICATION),--require-siem-certification) --min-siem-delivered "$(or $(MIN_SIEM_DELIVERED),1)" --max-siem-dead-letter "$(or $(MAX_SIEM_DEAD_LETTER),0)" --upgrade-rollout "$(or $(UPGRADE_ROLLOUT),build/upgrade/rollout-plan.json)" $(if $(REQUIRE_AGENT_GROUPS),--require-agent-groups) --soak-readiness "$(or $(SOAK_READINESS),build/performance/soak-readiness.json)" --min-soak-hours "$(or $(SOAK_MIN_HOURS),24)" --max-dropped-events "$(or $(SOAK_MAX_DROPPED_EVENTS),0)" --production-readiness-gate "$(or $(PRODUCTION_READINESS_GATE),build/production-readiness/production-readiness-gate.json)" --deployment-diagnostics-gate "$(or $(DEPLOYMENT_DIAGNOSTICS_GATE),build/deploy/deployment-diagnostics-gate.json)" --backup-readiness-gate "$(or $(BACKUP_READINESS_GATE),build/backup/backup-readiness-gate.json)" $(if $(REQUIRE_TLS),--require-tls) $(if $(REQUIRE_STATE_BACKEND),--require-state-backend) $(if $(PLUGIN_GATE),--plugin-gate "$(PLUGIN_GATE)") $(if $(PLUGIN_CATALOG_GATE),--plugin-catalog-gate "$(PLUGIN_CATALOG_GATE)") $(if $(REQUIRE_PLUGIN_GATE),--require-plugin-gate) $(if $(REQUIRE_PLUGIN_SIGNATURE),--require-plugin-signature) $(if $(REQUIRE_PLUGIN_PERMISSIONS),--require-plugin-permissions) --onboarding-manifest "$(or $(ONBOARDING_MANIFEST),build/onboarding/onboarding-manifest.json)" --min-onboarding-checks "$(or $(MIN_ONBOARDING_CHECKS),5)" $(foreach check,$(REQUIRED_ONBOARDING_CHECKS),--required-onboarding-check "$(check)") --out-json "$(or $(OUT_DIR),build/operator-certification)/operator-environment-certification-gate.json" --out-md "$(or $(OUT_DIR),build/operator-certification)/operator-environment-certification-gate.md"

open-source-readiness-gate:
	python3 scripts/ops/open-source-readiness-gate.py --release-gates "$(or $(RELEASE_GATES_JSON),build/release-gate-status.json)" --operations-readiness-gate "$(or $(OPERATIONS_READINESS_GATE),build/operations-readiness/operations-readiness-gate.json)" --open-source-operations "$(or $(OPERATIONS_EVIDENCE),build/open-source-operations.json)" --model-lifecycle-gate "$(or $(MODEL_LIFECYCLE_GATE),build/evaluation/model-lifecycle-gate.json)" --visual-regression-snapshots "$(or $(VISUAL_REGRESSION_SNAPSHOTS),build/visual-regression/visual-regression-snapshots.json)" --onboarding-manifest "$(or $(ONBOARDING_MANIFEST),build/onboarding/onboarding-manifest.json)" $(if $(PLUGIN_GATE),--plugin-gate "$(PLUGIN_GATE)") --external-approval "$(or $(EXTERNAL_APPROVAL),docs/project/external-approval-request-v1.2.3-rc.1.md)" --out-json "$(or $(OUT_DIR),build/open-source-readiness)/open-source-readiness-gate.json" --out-md "$(or $(OUT_DIR),build/open-source-readiness)/open-source-readiness-gate.md"

soak-sample:
	@if [ -z "$(STATUS_URL)" ] && [ -z "$(STATUS_JSON)" ]; then echo 'usage: make soak-sample STATUS_URL=http://localhost:18080/api/v1/status [SOAK_STARTED_AT_Elab validationH=...] [OUT=build/performance/soak-samples.json]'; exit 2; fi
	@python3 scripts/ops/collect-soak-sample.py $(if $(STATUS_URL),--status-url "$(STATUS_URL)") $(if $(STATUS_JSON),--status-json "$(STATUS_JSON)") $(if $(SOAK_HOST),--host "$(SOAK_HOST)") $(if $(SOAK_STARTED_AT_Elab validationH),--started-at-epoch "$(SOAK_STARTED_AT_Elab validationH)") --out "$(or $(OUT),build/performance/soak-samples.json)"

soak-readiness:
	@if [ -z "$(SOAK_SAMPLES)" ]; then echo 'usage: make soak-readiness SOAK_SAMPLES=build/performance/soak-samples.json [OUT_DIR=build/performance]'; exit 2; fi
	python3 scripts/ops/soak-readiness-report.py --samples "$(SOAK_SAMPLES)" --min-hours "$(or $(SOAK_MIN_HOURS),24)" --max-cpu-percent "$(or $(SOAK_MAX_CPU_PERCENT),25)" --max-memory-mb "$(or $(SOAK_MAX_MEMORY_MB),512)" --max-disk-mb "$(or $(SOAK_MAX_DISK_MB),4096)" --max-dropped-events "$(or $(SOAK_MAX_DROPPED_EVENTS),0)" --out-json "$(or $(OUT_DIR),build/performance)/soak-readiness.json" --out-md "$(or $(OUT_DIR),build/performance)/soak-readiness.md"

upgrade-rollout-plan:
	@if [ -z "$(FLEET_JSON)" ] || [ -z "$(TARGET_VERSION)" ]; then echo 'usage: make upgrade-rollout-plan FLEET_JSON=build/fleet/fleet.json TARGET_VERSION=v1.2.3 [OUT_DIR=build/upgrade] [BATCH_BY_GROUP=1]'; exit 2; fi
	python3 scripts/upgrade/rollout-plan.py --fleet "$(FLEET_JSON)" --target-version "$(TARGET_VERSION)" $(if $(PACKAGE_PATH),--package-path "$(PACKAGE_PATH)") $(if $(EXPECTED_SHA256),--expected-sha256 "$(EXPECTED_SHA256)") $(if $(SIGNATURE_PATH),--signature-path "$(SIGNATURE_PATH)") --canary-percent "$(or $(CANARY_PERCENT),10)" --max-batch-size "$(or $(MAX_BATCH_SIZE),25)" $(if $(BATCH_BY_GROUP),--batch-by-group) --out-json "$(or $(OUT_DIR),build/upgrade)/rollout-plan.json" --out-md "$(or $(OUT_DIR),build/upgrade)/rollout-plan.md"

onboarding-wizard:
	python3 scripts/ops/onboarding-wizard.py --out-dir "$(or $(OUT_DIR),build/onboarding)" --mode "$(or $(ONBOARDING_MODE),standalone)" --rest-port "$(or $(REST_PORT),18080)" --grpc-port "$(or $(GRPC_PORT),50051)" $(if $(POSTGRES_DSN),--postgres-dsn "$(POSTGRES_DSN)") $(if $(PROVIDAPT_SERVER_URL),--server-url "$(PROVIDAPT_SERVER_URL)") $(if $(POLICY_ENDPOINT),--policy-endpoint "$(POLICY_ENDPOINT)") $(if $(ONBOARDING_VM_HOSTS),--vm-hosts "$(ONBOARDING_VM_HOSTS)") $(if $(CHECK_RESULTS),--check-results "$(CHECK_RESULTS)")

onboarding-example-gate:
	python3 scripts/ops/onboarding-wizard.py --out-dir "$(or $(OUT_DIR),build/onboarding)" --mode standalone --rest-port 18080 --grpc-port 50051 --postgres-dsn "postgres://fixture/providapt?sslmode=require" --vm-hosts "ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" --check-results examples/onboarding-first-run/check-results.json

plugin-release-gate:
	@if [ -z "$(PLUGIN_MANIFEST)" ]; then echo 'usage: make plugin-release-gate PLUGIN_MANIFEST=path/plugin.json [PLUGIN_SIGNATURE=path/plugin.json.sig]'; exit 2; fi
	python3 scripts/ops/plugin-release-gate.py --manifest "$(PLUGIN_MANIFEST)" $(if $(PLUGIN_SIGNATURE),--signature "$(PLUGIN_SIGNATURE)") $(if $(ALLOW_UNSIGNED_PLUGIN),--allow-unsigned) --out-json "$(or $(OUT_DIR),build/plugins)/plugin-release-gate.json" --out-md "$(or $(OUT_DIR),build/plugins)/plugin-release-gate.md"

plugin-catalog-gate:
	python3 scripts/ops/plugin-catalog-gate.py $(foreach gate,$(PLUGIN_GATES),--plugin-gate "$(gate)") $(if $(REQUIRE_PLUGINS),--require-plugins) $(if $(REQUIRE_PLUGIN_SIGNATURE),--require-signatures) $(if $(REQUIRE_PLUGIN_PERMISSIONS),--require-permissions) --out-json "$(or $(OUT_DIR),build/plugins)/plugin-catalog-gate.json" --out-md "$(or $(OUT_DIR),build/plugins)/plugin-catalog-gate.md"

plugin-example-gates:
	python3 scripts/ops/plugin-release-gate.py --manifest examples/plugins/sample-detector/plugin.json --signature examples/plugins/sample-detector/sample-detector-1.0.0.bundle.sig --out-json "$(or $(OUT_DIR),build/plugins/sample-detector)/plugin-release-gate.json" --out-md "$(or $(OUT_DIR),build/plugins/sample-detector)/plugin-release-gate.md"
	python3 scripts/ops/plugin-catalog-gate.py --plugin-gate "$(or $(OUT_DIR),build/plugins/sample-detector)/plugin-release-gate.json" --require-plugins --require-signatures --require-permissions --out-json "$(or $(OUT_DIR),build/plugins)/plugin-catalog-gate.json" --out-md "$(or $(OUT_DIR),build/plugins)/plugin-catalog-gate.md"

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
	@if [ -z "$(PROVIDAPT_VM_HOSTS)" ]; then echo 'usage: make deploy-vms PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-slave.$(TAILSCALE_DOMAIN) centos@vm-centos-slave.$(TAILSCALE_DOMAIN) ubuntu@vm-ubuntu-master.$(TAILSCALE_DOMAIN)" [PROVIDAPT_BIN=build/bin/providaptd]'; exit 2; fi
	bash scripts/deploy/deploy-vms.sh

verify-vm-fleet:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'usage: make verify-vm-fleet PROVIDAPT_SERVER_URL=http://vm-ubuntu-master.$(TAILSCALE_DOMAIN):18080 [EXPECTED_COMMIT=...]'; exit 2; fi
	@python3 scripts/deploy/verify-vm-fleet.py --server "$(PROVIDAPT_SERVER_URL)" --min-agents "$(or $(MIN_AGENTS),3)" --min-healthy "$(or $(MIN_HEALTHY),3)" --max-report-age-seconds "$(or $(MAX_REPORT_AGE_SECONDS),30)" $(if $(EXPECTED_COMMIT),--expected-commit "$(EXPECTED_COMMIT)") --out-json "$(or $(OUT_DIR),build/deploy)/vm-fleet-verification.json" --out-md "$(or $(OUT_DIR),build/deploy)/vm-fleet-verification.md"

verify-vm-open-source-residue:
	@if [ -z "$(PROVIDAPT_VM_HOSTS)" ] && [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'usage: make verify-vm-open-source-residue PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080'; exit 2; fi
	@python3 scripts/deploy/vm-open-source-residue.py $(foreach host,$(PROVIDAPT_VM_HOSTS),--host "$(host)") $(if $(PROVIDAPT_SERVER_URL),--server-url "$(PROVIDAPT_SERVER_URL)") --timeout-seconds "$(or $(SSH_TIMEOUT_SECONDS),12)" --out-json "$(or $(OUT_DIR),build/deploy)/vm-open-source-residue.json" --out-md "$(or $(OUT_DIR),build/deploy)/vm-open-source-residue.md"

verify-vm-config:
	@if [ -z "$(PROVIDAPT_CONFIG)" ]; then echo 'usage: make verify-vm-config PROVIDAPT_CONFIG=/path/to/providapt.toml [VM_CONTROL_HOST=$(VM_CONTROL_HOST)]'; exit 2; fi
	python3 scripts/deploy/configure-vm-endpoints.py "$(PROVIDAPT_CONFIG)" --control-host "$(VM_CONTROL_HOST)"

visual-regression-snapshots:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'usage: make visual-regression-snapshots PROVIDAPT_SERVER_URL=http://127.0.0.1:18080 [ALERT_ID=p:100] [DRY_RUN=1] [BASELINE=build/visual-regression/visual-regression-snapshots.json] [PROMOTE_BASELINE=build/visual-regression/baseline]'; exit 2; fi
	@python3 scripts/ops/visual-regression-snapshots.py --server "$(PROVIDAPT_SERVER_URL)" --alert-id "$(or $(ALERT_ID),p:100)" $(if $(DRY_RUN),--dry-run) $(if $(BASELINE),--baseline "$(BASELINE)") $(if $(PROMOTE_BASELINE),--promote-baseline "$(PROMOTE_BASELINE)") --out-dir "$(or $(OUT_DIR),build/visual-regression)"

visual-regression-gate:
	python3 scripts/ops/visual-regression-gate.py --manifest "$(or $(VISUAL_REGRESSION_MANIFEST),build/visual-regression/visual-regression-snapshots.json)" $(if $(ALLOW_PLANNED_VISUALS),--allow-planned --allow-missing-files --allow-missing-hash --allow-missing-dom-assertions) $(if $(WARN_ON_VISUAL_CHANGED),--warn-on-changed) --out-json "$(or $(OUT_DIR),build/visual-regression)/visual-regression-gate.json" --out-md "$(or $(OUT_DIR),build/visual-regression)/visual-regression-gate.md"

trace-svg-stress:
	@if [ -z "$(PROVIDAPT_SERVER_URL)" ]; then echo 'usage: make trace-svg-stress PROVIDAPT_SERVER_URL=http://127.0.0.1:18080 [ALERT_IDS="p:100 p:200"] [OUT_DIR=build/trace-stress]'; exit 2; fi
	@python3 scripts/ops/trace-svg-stress.py --server "$(PROVIDAPT_SERVER_URL)" $(foreach alert,$(ALERT_IDS),--alert-id "$(alert)") --discover-limit "$(or $(TRACE_DISCOVER_LIMIT),3)" --max-latency-ms "$(or $(MAX_LATENCY_MS),1500)" --min-node-count "$(or $(MIN_TRACE_NODES),1)" --out-json "$(or $(OUT_DIR),build/trace-stress)/trace-svg-stress.json" --out-md "$(or $(OUT_DIR),build/trace-stress)/trace-svg-stress.md"

trace-svg-stress-example:
	python3 scripts/ops/trace-svg-stress.py --synthetic-alerts "$(or $(SYNTHETIC_ALERTS),2)" --synthetic-nodes "$(or $(SYNTHETIC_TRACE_NODES),250)" --max-latency-ms "$(or $(MAX_LATENCY_MS),1500)" --min-node-count "$(or $(MIN_TRACE_NODES),200)" --out-json "$(or $(OUT_DIR),build/trace-stress)/trace-svg-stress.json" --out-md "$(or $(OUT_DIR),build/trace-stress)/trace-svg-stress.md"

capture-enrichment-field-gate:
	@if [ -z "$(EVENTS)" ]; then echo 'usage: make capture-enrichment-field-gate EVENTS=path/events.ndjson [OUT_DIR=build/capture-quality]'; exit 2; fi
	python3 scripts/ops/capture-enrichment-field-gate.py $(foreach event,$(EVENTS),--events "$(event)") --min-events "$(or $(MIN_EVENTS),1)" --min-event-type-rate "$(or $(MIN_EVENT_TYPE_RATE),100)" --min-pid-rate "$(or $(MIN_PID_RATE),95)" --min-ppid-rate "$(or $(MIN_PPID_RATE),80)" --min-uid-rate "$(or $(MIN_UID_RATE),95)" --min-gid-rate "$(or $(MIN_GID_RATE),95)" --min-cmdline-rate "$(or $(MIN_CMDLINE_RATE),10)" --min-exe-path-rate "$(or $(MIN_EXE_PATH_RATE),10)" --min-pathname-rate "$(or $(MIN_PATHNAME_RATE),80)" --min-network-tuple-rate "$(or $(MIN_NETWORK_TUPLE_RATE),80)" --out-json "$(or $(OUT_DIR),build/capture-quality)/capture-enrichment-field-gate.json" --out-md "$(or $(OUT_DIR),build/capture-quality)/capture-enrichment-field-gate.md"

collect-vm-capture-evidence:
	@if [ -z "$(PROVIDAPT_VM_HOSTS)" ]; then echo 'usage: make collect-vm-capture-evidence PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave" [REMOTE_DIR=/var/log/providapt]'; exit 2; fi
	python3 scripts/ops/collect-vm-capture-evidence.py $(foreach host,$(PROVIDAPT_VM_HOSTS),--host "$(host)") --remote-dir "$(or $(REMOTE_DIR),/var/log/providapt)" --timeout-seconds "$(or $(SSH_TIMEOUT_SECONDS),15)" --gate-timeout-seconds "$(or $(CAPTURE_GATE_TIMEOUT_SECONDS),60)" --max-files "$(or $(MAX_VM_EVENT_FILES),5)" --lines-per-file "$(or $(VM_EVENT_LINES),5000)" --network-lines "$(or $(VM_NETWORK_LINES),200)" --out-dir "$(or $(OUT_DIR),build/vm-capture-evidence)" $(if $(SKIP_CAPTURE_GATE),--skip-gate)


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

graph-dataset:
	@if [ -z "$(EVENTS)" ] || [ -z "$(GROUND_TRUTH)" ]; then echo 'usage: make graph-dataset EVENTS=/var/log/providapt GROUND_TRUTH=/var/log/providapt/ground-truth [ALERT_FEEDBACK=/var/log/providapt/alert-feedback.ndjson] [OUT_DIR=build/ml-dataset]'; exit 2; fi
	python3 scripts/evaluation/build_graph_training_dataset.py --events "$(EVENTS)" $(if $(NORMAL_EVENTS),--normal-events "$(NORMAL_EVENTS)") --ground-truth "$(GROUND_TRUTH)" $(if $(ALERT_FEEDBACK),--alert-feedback "$(ALERT_FEEDBACK)") --out-dir "$(or $(OUT_DIR),build/ml-dataset)" --dataset-version "$(or $(DATASET_VERSION),dev)" --window-seconds "$(or $(WINDOW_SECONDS),300)" --negative-ratio "$(or $(NEGATIVE_RATIO),1)" --normal-window-events "$(or $(NORMAL_WINDOW_EVENTS),64)"

dataset-split-gate:
	@if [ -z "$(DATASET_MANIFEST)" ]; then echo 'usage: make dataset-split-gate DATASET_MANIFEST=build/ml-dataset/manifest.json'; exit 2; fi
	python3 scripts/evaluation/dataset_split_gate.py --manifest "$(DATASET_MANIFEST)" --min-records "$(or $(MIN_DATASET_RECORDS),1)" --min-train "$(or $(MIN_TRAIN_RECORDS),1)" --min-test "$(or $(MIN_TEST_RECORDS),1)" --min-val "$(or $(MIN_VAL_RECORDS),0)" $(if $(REQUIRE_DATASET_VERSION),--require-version) $(if $(REQUIRE_TRAIN_SPLIT),--require-train) $(if $(REQUIRE_TEST_SPLIT),--require-test) $(if $(REQUIRE_VAL_SPLIT),--require-val) $(if $(REQUIRE_BOTH_LABELS),--require-both-labels) $(if $(REQUIRE_DATASET_FILE_HASHES),--require-file-hashes) --out-json "$(or $(OUT_DIR),build/evaluation)/dataset-split-gate.json" --out-md "$(or $(OUT_DIR),build/evaluation)/dataset-split-gate.md"

graph-augment:
	@if [ -z "$(GRAPH_DATASET)" ]; then echo 'usage: make graph-augment GRAPH_DATASET=build/ml-dataset/graphs.jsonl [OUT_DIR=build/ml-dataset-large] [RECORDS=200000]'; exit 2; fi
	python3 scripts/evaluation/augment_graph_dataset.py --input "$(GRAPH_DATASET)" --out-dir "$(or $(OUT_DIR),build/ml-dataset-large)" --records "$(or $(RECORDS),200000)" --dataset-version "$(or $(DATASET_VERSION),synthetic-large)" $(if $(SOURCE_MANIFEST),--source-manifest "$(SOURCE_MANIFEST)") $(if $(FEATURE_SCHEMA),--feature-schema "$(FEATURE_SCHEMA)")

graph-train:
	$(or $(CONDA_RUN),conda run -n $(or $(CONDA_ENV),torch_py39)) python scripts/evaluation/train_graph_detector.py --dataset "$(or $(GRAPH_DATASET),build/ml-dataset/graphs.jsonl)" --out-dir "$(or $(OUT_DIR),build/ml-model)" --architecture "$(or $(ARCH),gcn)" --epochs "$(or $(Elab validationHS),20)" --hidden-dim "$(or $(HIDDEN_DIM),32)" --device "$(or $(DEVICE),auto)" --pos-weight "$(or $(POS_WEIGHT),auto)"

ml-training-pipeline:
	@if [ -z "$(EVENTS)" ] || [ -z "$(GROUND_TRUTH)" ] || [ -z "$(MODEL_VERSION)" ]; then echo 'usage: make ml-training-pipeline EVENTS=... GROUND_TRUTH=... MODEL_VERSION=... [MODEL_NAME=graph-detector]'; exit 2; fi
	$(MAKE) graph-dataset EVENTS="$(EVENTS)" GROUND_TRUTH="$(GROUND_TRUTH)" $(if $(ALERT_FEEDBACK),ALERT_FEEDBACK="$(ALERT_FEEDBACK)") OUT_DIR="$(or $(DATASET_OUT_DIR),build/ml-dataset)" DATASET_VERSION="$(or $(DATASET_VERSION),$(MODEL_VERSION))"
	$(MAKE) graph-train GRAPH_DATASET="$(or $(DATASET_OUT_DIR),build/ml-dataset)/graphs.jsonl" OUT_DIR="$(or $(MODEL_OUT_DIR),build/ml-model)" ARCH="$(or $(ARCH),gcn)" Elab validationHS="$(or $(Elab validationHS),20)"
	$(MAKE) model-register DATASET_MANIFEST="$(or $(DATASET_OUT_DIR),build/ml-dataset)/manifest.json" MODEL_NAME="$(or $(MODEL_NAME),graph-detector)" MODEL_VERSION="$(MODEL_VERSION)" MODEL_METRICS="$(or $(MODEL_OUT_DIR),build/ml-model)/metrics.json" MODEL_ARTIFACT="$(or $(MODEL_OUT_DIR),build/ml-model)/model.pt" FEATURE_SCHEMA="$(or $(DATASET_OUT_DIR),build/ml-dataset)/feature_schema.json" MODEL_REGISTRY="$(or $(MODEL_REGISTRY),build/model-registry.json)" NOTES="Graph detector training pipeline"
	$(MAKE) model-closed-loop DATASET_MANIFEST="$(or $(DATASET_OUT_DIR),build/ml-dataset)/manifest.json" MODEL_METRICS="$(or $(MODEL_OUT_DIR),build/ml-model)/metrics.json" MODEL_REGISTRY="$(or $(MODEL_REGISTRY),build/model-registry.json)" MODEL_NAME="$(or $(MODEL_NAME),graph-detector)" MODEL_VERSION="$(MODEL_VERSION)" $(if $(ALERT_FEEDBACK),ALERT_FEEDBACK="$(ALERT_FEEDBACK)")

ml-readiness-gate:
	@if [ -z "$(DATASET_MANIFEST)" ] || [ -z "$(MODEL_METRICS)" ]; then echo 'usage: make ml-readiness-gate DATASET_MANIFEST=... MODEL_METRICS=... [MODEL_GATE=...]'; exit 2; fi
	python3 scripts/evaluation/ml-readiness-gate.py --dataset-manifest "$(DATASET_MANIFEST)" --metrics "$(MODEL_METRICS)" $(if $(MODEL_GATE),--model-gate "$(MODEL_GATE)") $(if $(EVENTS),--events "$(EVENTS)") $(if $(NORMAL_EVENTS),--normal-events "$(NORMAL_EVENTS)") $(if $(GROUND_TRUTH),--ground-truth "$(GROUND_TRUTH)") --window-seconds "$(or $(WINDOW_SECONDS),300)" --min-graphs "$(or $(MIN_GRAPHS),1000)" --min-source-events "$(or $(MIN_SOURCE_EVENTS),10000)" --min-malicious-graphs "$(or $(MIN_MALICIOUS_GRAPHS),100)" --min-benign-graphs "$(or $(MIN_BENIGN_GRAPHS),100)" --min-truth-match-rate "$(or $(MIN_TRUTH_MATCH_RATE),80)" --min-cmdline-rate "$(or $(MIN_CMDLINE_RATE),10)" --min-path-rate "$(or $(MIN_PATH_RATE),10)" --min-precision "$(or $(MIN_PRECISION),70)" --min-recall "$(or $(MIN_RECALL),80)" --min-f1 "$(or $(MIN_F1),70)" --min-test-support "$(or $(MIN_TEST_SUPPORT),100)" --out-json "$(or $(OUT_DIR),build/ml-readiness)/ml-readiness-gate.json" --out-md "$(or $(OUT_DIR),build/ml-readiness)/ml-readiness-gate.md"

alert-quality:
	@if [ -z "$(ALERTS)" ]; then echo 'usage: make alert-quality ALERTS=/var/log/providapt/alerts.ndjson [ALERT_FEEDBACK=/var/log/providapt/alert-feedback.ndjson] [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/alert_quality_report.py "$(ALERTS)" $(if $(ALERT_FEEDBACK),--feedback "$(ALERT_FEEDBACK)") --out-json "$(or $(OUT_DIR),build/evaluation)/alert-quality.json" --out-md "$(or $(OUT_DIR),build/evaluation)/alert-quality.md"

detection-quality:
	@if [ -z "$(COVERAGE_JSON)" ]; then echo 'usage: make detection-quality COVERAGE_JSON=build/evaluation-dataset/coverage.json ALERT_QUALITY_JSON=build/evaluation/alert-quality.json [ALERTS=/var/log/providapt/alerts.ndjson ALERT_FEEDBACK=/var/log/providapt/alert-feedback.ndjson] [OUT_DIR=build/evaluation]'; exit 2; fi
	@if [ -z "$(ALERT_QUALITY_JSON)" ] && [ -z "$(ALERTS)" ]; then echo 'set ALERT_QUALITY_JSON or ALERTS'; exit 2; fi
	$(if $(ALERT_QUALITY_JSON),,python3 scripts/evaluation/alert_quality_report.py "$(ALERTS)" $(if $(ALERT_FEEDBACK),--feedback "$(ALERT_FEEDBACK)") --out-json "$(or $(OUT_DIR),build/evaluation)/alert-quality.json" --out-md "$(or $(OUT_DIR),build/evaluation)/alert-quality.md")
	python3 scripts/evaluation/detection_quality_report.py --coverage "$(COVERAGE_JSON)" --alert-quality "$(or $(ALERT_QUALITY_JSON),$(or $(OUT_DIR),build/evaluation)/alert-quality.json)" --out-json "$(or $(OUT_DIR),build/evaluation)/detection-quality.json" --out-md "$(or $(OUT_DIR),build/evaluation)/detection-quality.md"

attack-coverage-plan:
	@if [ -z "$(DETECTION_QUALITY_JSON)" ]; then echo 'usage: make attack-coverage-plan DETECTION_QUALITY_JSON=build/evaluation/detection-quality.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/attack_coverage_plan.py --detection-quality "$(DETECTION_QUALITY_JSON)" --out-json "$(or $(OUT_DIR),build/evaluation)/attack-coverage-plan.json" --out-md "$(or $(OUT_DIR),build/evaluation)/attack-coverage-plan.md"

model-register:
	@if [ -z "$(DATASET_MANIFEST)" ] || [ -z "$(MODEL_NAME)" ] || [ -z "$(MODEL_VERSION)" ]; then echo 'usage: make model-register DATASET_MANIFEST=build/evaluation-dataset/manifest.json MODEL_NAME=detector MODEL_VERSION=1.0.0 [MODEL_METRICS=metrics.json] [MODEL_REGISTRY=build/model-registry.json]'; exit 2; fi
	python3 scripts/evaluation/model_registry.py register --manifest "$(DATASET_MANIFEST)" --registry "$(or $(MODEL_REGISTRY),build/model-registry.json)" --model-name "$(MODEL_NAME)" --model-version "$(MODEL_VERSION)" $(if $(MODEL_METRICS),--metrics "$(MODEL_METRICS)") $(if $(MODEL_ARTIFACT),--artifact "$(MODEL_ARTIFACT)") $(if $(FEATURE_SCHEMA),--feature-schema "$(FEATURE_SCHEMA)") $(if $(COMMIT),--commit "$(COMMIT)") $(if $(NOTES),--notes "$(NOTES)")

model-drift:
	@if [ -z "$(BASELINE_MANIFEST)" ] || [ -z "$(CANDIDATE_MANIFEST)" ]; then echo 'usage: make model-drift BASELINE_MANIFEST=old/manifest.json CANDIDATE_MANIFEST=new/manifest.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/model_registry.py drift --baseline "$(BASELINE_MANIFEST)" --candidate "$(CANDIDATE_MANIFEST)" --threshold-percent "$(or $(DRIFT_THRESHOLD_PERCENT),20)" --out-json "$(or $(OUT_DIR),build/evaluation)/model-drift.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-drift.md"

model-closed-loop:
	@if [ -z "$(DATASET_MANIFEST)" ] || [ -z "$(MODEL_METRICS)" ]; then echo 'usage: make model-closed-loop DATASET_MANIFEST=... MODEL_METRICS=... [MODEL_REGISTRY=build/model-registry.json]'; exit 2; fi
	python3 scripts/evaluation/model_closed_loop.py --dataset-manifest "$(DATASET_MANIFEST)" --metrics "$(MODEL_METRICS)" --registry "$(or $(MODEL_REGISTRY),build/model-registry.json)" --model-name "$(or $(MODEL_NAME),graph-detector)" --model-version "$(MODEL_VERSION)" $(if $(MODEL_DRIFT_JSON),--drift-report "$(MODEL_DRIFT_JSON)") $(if $(ALERT_FEEDBACK),--feedback "$(ALERT_FEEDBACK)") $(if $(REQUIRE_FEEDBACK),--require-feedback) --min-precision "$(or $(MIN_PRECISION),70)" --min-recall "$(or $(MIN_RECALL),80)" --min-f1 "$(or $(MIN_F1),70)" --out-json "$(or $(OUT_DIR),build/evaluation)/model-closed-loop.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-closed-loop.md"

model-feature-schema:
	python3 scripts/evaluation/model_registry.py export-schema --version "$(or $(FEATURE_SCHEMA_VERSION),1)" --out "$(or $(OUT_DIR),build/evaluation)/model-feature-schema.json"

model-feature-schema-check:
	@if [ -z "$(FEATURE_SCHEMA)" ]; then echo 'usage: make model-feature-schema-check FEATURE_SCHEMA=build/evaluation/model-feature-schema.json [OUT_DIR=build/evaluation]'; exit 2; fi
	python3 scripts/evaluation/model_registry.py validate-schema --schema-file "$(FEATURE_SCHEMA)" --out "$(or $(OUT_DIR),build/evaluation)/model-feature-schema-check.json" --strict

model-deploy-gate:
	@if [ -z "$(MODEL_REGISTRY)" ] || [ -z "$(MODEL_NAME)" ] || [ -z "$(MODEL_VERSION)" ]; then echo 'usage: make model-deploy-gate MODEL_REGISTRY=build/model-registry.json MODEL_NAME=detector MODEL_VERSION=1.0.0'; exit 2; fi
	python3 scripts/evaluation/model_deploy_gate.py --registry "$(MODEL_REGISTRY)" --model-name "$(MODEL_NAME)" --model-version "$(MODEL_VERSION)" $(if $(DETECTION_QUALITY_JSON),--detection-quality "$(DETECTION_QUALITY_JSON)") $(if $(MODEL_DRIFT_JSON),--drift-report "$(MODEL_DRIFT_JSON)") $(if $(FEATURE_SCHEMA_CHECK_JSON),--feature-schema-check "$(FEATURE_SCHEMA_CHECK_JSON)") --min-precision "$(or $(MIN_PRECISION),70)" --min-recall "$(or $(MIN_RECALL),80)" --out-json "$(or $(OUT_DIR),build/evaluation)/model-deploy-gate.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-deploy-gate.md"

model-lifecycle-gate:
	@if [ -z "$(MODEL_CLOSED_LOOP_JSON)" ] || [ -z "$(MODEL_DEPLOY_GATE_JSON)" ]; then echo 'usage: make model-lifecycle-gate MODEL_CLOSED_LOOP_JSON=... MODEL_DEPLOY_GATE_JSON=... [MODEL_APPROVAL=...] [REQUIRED_FEEDBACK_LABELS=\"true_positive false_positive benign duplicate\"]'; exit 2; fi
	python3 scripts/evaluation/model_lifecycle_gate.py --closed-loop "$(MODEL_CLOSED_LOOP_JSON)" --deploy-gate "$(MODEL_DEPLOY_GATE_JSON)" $(if $(MODEL_DRIFT_JSON),--drift-report "$(MODEL_DRIFT_JSON)") $(if $(MODEL_APPROVAL),--approval "$(MODEL_APPROVAL)") --min-feedback-records "$(or $(MIN_FEEDBACK_RECORDS),25)" --min-reviewed-labels "$(or $(MIN_REVIEWED_LABELS),10)" $(foreach label,$(REQUIRED_FEEDBACK_LABELS),--required-feedback-label "$(label)") --min-feedback-per-label "$(or $(MIN_FEEDBACK_PER_LABEL),1)" --min-baseline-days "$(or $(MIN_BASELINE_DAYS),7)" $(if $(REQUIRE_MODEL_APPROVAL),--require-approval) --out-json "$(or $(OUT_DIR),build/evaluation)/model-lifecycle-gate.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-lifecycle-gate.md"

model-lifecycle-example-gate:
	python3 scripts/evaluation/model_lifecycle_gate.py --closed-loop examples/model-lifecycle/closed-loop.json --deploy-gate examples/model-lifecycle/deploy-gate.json --drift-report examples/model-lifecycle/drift.json --approval examples/model-lifecycle/approval.json --require-approval --required-feedback-label true_positive --required-feedback-label false_positive --required-feedback-label benign --required-feedback-label duplicate --out-json "$(or $(OUT_DIR),build/evaluation)/model-lifecycle-gate.json" --out-md "$(or $(OUT_DIR),build/evaluation)/model-lifecycle-gate.md"

verify-capture:
	@bash test/integration/attack-scenarios/verify_capture.sh

loader-smoke:
	@bash test/integration/loader_smoke.sh

docker-build:
	docker build -t providapt:latest -f build/docker/Dockerfile.ubuntu .

upgrade-artifact:
	@if [ -z "$(ARTIFACT)" ] || [ -z "$(VERSION)" ] || [ -z "$(BASE_URL)" ]; then echo 'usage: make upgrade-artifact ARTIFACT=dist/providapt.tar.gz VERSION=v1.2.4 BASE_URL=http://host:19090/artifacts [SIGNING_KEY=secret]'; exit 2; fi
	python3 scripts/release/build_upgrade_artifact.py --artifact "$(ARTIFACT)" --version "$(VERSION)" --base-url "$(BASE_URL)" --out-dir "$(or $(OUT_DIR),build/upgrade-artifacts)" $(if $(MINIMUM_VERSION),--minimum-version "$(MINIMUM_VERSION)") $(if $(RELEASE_NOTES),--release-notes "$(RELEASE_NOTES)") $(if $(PUBLISHED_AT),--published-at "$(PUBLISHED_AT)") $(if $(SIGNING_KEY),--signing-key "$(SIGNING_KEY)")

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
	@echo '  make graph-dataset    Build graph ML dataset from events and labels'
	@echo '  make dataset-split-gate Gate dataset version, split, label, and hash evidence'
	@echo '  make graph-augment    Expand captured graphs into a large synthetic dataset'
	@echo '  make graph-train      Train GCN/GAT/GraphSAGE with conda torch_py39'
	@echo '  make alert-quality    Export annotated alert precision and review metrics'
	@echo '  make detection-quality Merge coverage and alert quality into precision/recall/F1'
	@echo '  make attack-coverage-plan Plan safe simulations for missed ATT&CK techniques'
	@echo '  make model-deploy-gate MODEL_REGISTRY=... MODEL_NAME=... MODEL_VERSION=... Gate model deployment'
	@echo '  make model-lifecycle-gate MODEL_CLOSED_LOOP_JSON=... MODEL_DEPLOY_GATE_JSON=... Build model promotion packet'
	@echo '  make model-lifecycle-example-gate Run sample model lifecycle promotion fixture'
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
	@echo '  make verify-vm-open-source-residue Detect removed API key/activation residue on VMs'
	@echo ''
	@echo 'Distribution:'
	@echo '  make dist             Build all package formats (.deb/.rpm/.tar.gz)'
	@echo '  make dist-deb         Build the .deb package'
	@echo '  make dist-rpm         Build the .rpm package'
	@echo '  make dist-tar         Build the portable tarball'
	@echo '  make release-open-source Build open-source release artifacts, SBOMs, checksums, scans, and readiness report'
	@echo '  make github-actions-evidence Collect structured GitHub Actions evidence'
	@echo '  make release-gates     Collect CI, scanner, approval, and artifact gate status'
	@echo '  make release-security-local-gate Run local govulncheck/Grype/Trivy evidence capture'
	@echo '  make security-scan-manifest Generate current-commit security scan manifest from local scanner outputs'
	@echo '  make artifact-signing-gate Validate checksums, artifact hashes, and signature evidence'
	@echo '  make release-evidence-consistency-gate Validate release commit/version evidence consistency'
	@echo '  make operator-release-gate Aggregate open-source release evidence and blockers'
	@echo '  make release-blocker-backlog Convert release blockers to action items'
	@echo '  make open-source-readiness-backlog Convert open-source readiness blockers to action items'
	@echo '  make open-source-development-backlog LOCAL_ONLY=1 Generate prioritized open-source backlog'
	@echo '  make open-source-milestone ALLOW_MISSING=1 Aggregate local open-source milestone evidence'
	@echo '  make open-source-evidence-summary ALLOW_MISSING=1 Summarize release blockers from local evidence'
	@echo '  make open-source-local-closure Build local closure matrix for remaining open-source release tasks'
	@echo '  make package-smoke-matrix Test dist packages in Ubuntu/Rocky containers'
	@echo ''
	@echo 'Operations:'
	@echo '  make ops-secret-template Generate production secret env template'
	@echo '  make ops-secret-validate SECRET_ENV=... Validate production secret env file'
	@echo '  make ops-tls-bootstrap TLS CA, server, and agent certificate bootstrap'
	@echo '  make ops-tls-check CERTS="..." Check TLS certificate expiry'
	@echo '  make ops-postgres-drill Run PostgreSQL backup/restore drill'
	@echo '  make ops-fleet-list List control-plane fleet state'
	@echo '  make ops-fleet-action FLEET_AGENTS=... FLEET_STATE=approved|quarantined|revoked Apply fleet lifecycle action'
	@echo '  make ops-fleet-plan FLEET_OPERATION=... Generate fleet lifecycle plan'
	@echo '  make ops-siem-verify Queue and verify SIEM test delivery'
	@echo '  make ops-rbac-audit PROVIDAPT_CONFIG=... Audit RBAC and tenant scoping'
	@echo '  make policy-approval-gate Gate RBAC, tenant, audit, and approval workflow evidence'
	@echo '  make rbac-hardening-example-gate Run sample RBAC, audit, role review, and certification fixture'
	@echo '  make backup-readiness-gate Gate backup, restore, and cutover evidence'
	@echo '  make support-bundle-gate Gate support bundle redaction and audit evidence'
	@echo '  make deployment-diagnostics-gate Gate runtime deployment diagnostics evidence'
	@echo '  make trace-svg-stress PROVIDAPT_SERVER_URL=... ALERT_IDS="..." Stress Trace SVG layouts'
	@echo '  make trace-svg-stress-example Run synthetic local Trace SVG stress fixture'
	@echo '  make collect-vm-capture-evidence PROVIDAPT_VM_HOSTS="..." Collect VM NDJSON and gate field enrichment'
	@echo '  make install-delivery-check Validate installer, config, service, and handoff docs'
	@echo '  make observability-pack-check Validate Prometheus, alert rules, dashboard, and live metrics'
	@echo '  make visual-regression-snapshots Capture dashboard and trace viewer screenshots'
	@echo '  make visual-regression-gate Gate captured visual regression evidence'
	@echo '  make capture-enrichment-field-gate EVENTS=... Gate capture/enrichment field coverage'
	@echo '  make security-hardening-gate Validate production config and systemd hardening'
	@echo '  make scheduled-report-plan Generate executive/compliance report schedule'
	@echo '  make open-source-operations Aggregate release, secret, PostgreSQL, and detection evidence'
	@echo '  make operations-readiness-gate      Aggregate production operations readiness evidence'
	@echo '  make open-source-readiness-gate Aggregate open-source readiness evidence'
	@echo '  make soak-sample STATUS_URL=... Append one long-duration soak sample'
	@echo '  make soak-readiness SOAK_SAMPLES=... Check long-duration performance budgets'
	@echo '  make upgrade-rollout-plan FLEET_JSON=... TARGET_VERSION=... [BATCH_BY_GROUP=1] Plan staged upgrades'
	@echo '  make onboarding-wizard Generate first-run config and checklist'
	@echo '  make onboarding-example-gate Run sample first-run onboarding fixture'
	@echo '  make plugin-release-gate PLUGIN_MANIFEST=... Validate plugin signing and compatibility'
	@echo '  make plugin-example-gates Run signed sample plugin release and catalog gates'
	@echo '  make operator-env-certification-gate Aggregate operator environment certification evidence'
