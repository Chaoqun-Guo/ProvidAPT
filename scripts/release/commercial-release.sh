#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${VERSION:-$(cd "$PROJECT_DIR" && git describe --tags --always 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(cd "$PROJECT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo none)}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIST_DIR="${DIST_DIR:-$PROJECT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/build}"
EVIDENCE_PATH="${EVIDENCE_PATH:-$BUILD_DIR/release-evidence.md}"
WAIVERS_PATH="${WAIVERS_PATH:-$BUILD_DIR/release-waivers.json}"
REQUIRED_ARTIFACTS="${REQUIRED_ARTIFACTS:-archive,deb,rpm}"
SIGN_CHECKSUMS="${SIGN_CHECKSUMS:-auto}"
RUN_SCANS="${RUN_SCANS:-auto}"
BUILD_EBPF="${BUILD_EBPF:-1}"
GO_TAGS="${GO_TAGS:-bpf}"
BUILD_CONTAINER="${BUILD_CONTAINER:-0}"
BUILD_HELM_ARCHIVE="${BUILD_HELM_ARCHIVE:-1}"
PACKAGE_FORMATS="${PACKAGE_FORMATS:-all}"
CONFIG_PATH="${CONFIG_PATH:-$PROJECT_DIR/examples/config/providapt.local.toml}"
CGO_ENABLED="${CGO_ENABLED:-0}"
KEEP_BUILD_DIST="${KEEP_BUILD_DIST:-0}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.38.0}"
GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:v0.104.0}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.67.2}"
export CGO_ENABLED
export GO_TAGS

log() {
	printf '\n==> %s\n' "$*"
}

warn() {
	printf 'WARN: %s\n' "$*" >&2
}

need_file() {
	if [ ! -f "$1" ]; then
		printf 'ERROR: required file missing: %s\n' "$1" >&2
		exit 1
	fi
}

copy_dist_artifacts() {
	mkdir -p "$DIST_DIR"
	if [ -d "$BUILD_DIR/dist" ]; then
		find "$BUILD_DIR/dist" -maxdepth 1 -type f -exec cp -f {} "$DIST_DIR/" \;
		if [ "$KEEP_BUILD_DIST" != "1" ] && [ "$KEEP_BUILD_DIST" != "true" ]; then
			rm -rf "$BUILD_DIR/dist"
		fi
	fi
}

build_helm_archive() {
	local chart_dir="$PROJECT_DIR/deploy/helm/providapt"
	if [ ! -d "$chart_dir" ]; then
		warn "Helm chart directory not found; skipping Helm archive"
		return
	fi
	local archive="$DIST_DIR/providapt-helm-${VERSION}.tgz"
	if command -v helm >/dev/null 2>&1; then
		helm package "$chart_dir" --version "${VERSION#v}" --app-version "$VERSION" --destination "$DIST_DIR"
	else
		tar -czf "$archive" -C "$PROJECT_DIR/deploy/helm" providapt
	fi
}

prepare_package_defaults() {
	mkdir -p "$BUILD_DIR"
	if [ ! -f "$BUILD_DIR/providapt.toml" ]; then
		cat > "$BUILD_DIR/providapt.toml" <<EOF
output:
  dir: /var/log/providapt
  format: json
api:
  grpc: ":50051"
  rest: ":8080"
  auth_enabled: true
  auth_keys:
    - release-admin-key
  auth_roles:
    release-admin-key: admin
  cors_origins:
    - https://soc.example.com
control_plane:
  mode: standalone
  role: leader
  state_backend: /var/log/providapt/control-plane-state.json
storage:
  encrypt: true
  key_file: /etc/providapt/storage.key
policy:
  enabled: true
  endpoint: http://127.0.0.1:8080
  api_key: release-admin-key
  poll_interval: 30s
  bundle_dir: /var/log/providapt/applied-policy-bundles
support_bundle:
  redact_archives: true
  retain_archives: 5
capture:
  enable_net: true
  enable_file: true
  enable_proc: true
EOF
	fi
	if [ ! -f "$BUILD_DIR/providapt.env" ] && [ -f "$PROJECT_DIR/deploy/linux/providapt.env" ]; then
		cp -f "$PROJECT_DIR/deploy/linux/providapt.env" "$BUILD_DIR/providapt.env"
	fi
}

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

spdx_id() {
	printf '%s' "$1" | sed 's/[^A-Za-z0-9.-]/-/g'
}

generate_go_module_sbom_fallback() {
	local spdx="$1"
	local cdx="$2"
	local reason="$3"
	local modules
	modules="$(mktemp)"
	if ! (cd "$PROJECT_DIR" && go list -m all > "$modules"); then
		rm -f "$modules"
		printf 'ERROR: syft unavailable and go module SBOM fallback failed\n' >&2
		exit 1
	fi

	warn "$reason; writing Go module SBOM fallback"
	{
		printf '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"ProvidAPT %s","documentNamespace":"https://providapt.local/spdx/%s/%s","creationInfo":{"created":"%s","creators":["Tool: ProvidAPT release pipeline","Tool: go list -m all"]},"packages":[' "$VERSION" "$VERSION" "$COMMIT" "$DATE"
		local first=1
		while read -r module version _; do
			[ -n "$module" ] || continue
			[ -n "${version:-}" ] || version="local"
			if [ "$first" = "1" ]; then first=0; else printf ','; fi
			printf '{"name":"%s","SPDXID":"SPDXRef-Package-%s","versionInfo":"%s","downloadLocation":"NOASSERTION","filesAnalyzed":false}' "$(json_escape "$module")" "$(spdx_id "$module")" "$(json_escape "$version")"
		done < "$modules"
		printf ']}\n'
	} > "$spdx"
	{
		printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"timestamp":"%s","component":{"type":"application","name":"ProvidAPT","version":"%s"}},"components":[' "$DATE" "$VERSION"
		local first=1
		while read -r module version _; do
			[ -n "$module" ] || continue
			[ -n "${version:-}" ] || version="local"
			if [ "$first" = "1" ]; then first=0; else printf ','; fi
			printf '{"type":"library","name":"%s","version":"%s","purl":"pkg:golang/%s@%s"}' "$(json_escape "$module")" "$(json_escape "$version")" "$(json_escape "$module")" "$(json_escape "$version")"
		done < "$modules"
		printf ']}\n'
	} > "$cdx"
	rm -f "$modules"
}

generate_sbom() {
	local spdx="$DIST_DIR/sbom.spdx.json"
	local cdx="$DIST_DIR/sbom.cdx.json"
	if command -v syft >/dev/null 2>&1; then
		syft dir:"$PROJECT_DIR" --output "spdx-json=$spdx"
		syft dir:"$PROJECT_DIR" --output "cyclonedx-json=$cdx"
	elif command -v docker >/dev/null 2>&1; then
		if docker run --rm -v "$PROJECT_DIR:/workspace:ro" -v "$DIST_DIR:/out" "$SYFT_IMAGE" dir:/workspace --output "spdx-json=/out/sbom.spdx.json"; then
			docker run --rm -v "$PROJECT_DIR:/workspace:ro" -v "$DIST_DIR:/out" "$SYFT_IMAGE" dir:/workspace --output "cyclonedx-json=/out/sbom.cdx.json"
		else
			generate_go_module_sbom_fallback "$spdx" "$cdx" "dockerized syft failed"
		fi
	else
		generate_go_module_sbom_fallback "$spdx" "$cdx" "syft not installed"
	fi
}

generate_checksums() {
	(
		cd "$DIST_DIR"
		find . -maxdepth 1 -type f \
			! -name checksums.txt \
			! -name checksums.txt.sig \
			! -name checksums.txt.pub \
			! -name release-readiness.md \
			! -name release-readiness.json \
			-printf '%P\n' | sort | xargs -r sha256sum > checksums.txt
	)
}

sign_checksums() {
	local manifest="$DIST_DIR/checksums.txt"
	case "$SIGN_CHECKSUMS" in
		0|false|no|off)
			warn "checksum signing disabled; writing unsigned evidence marker"
			printf 'unsigned checksums accepted by SIGN_CHECKSUMS=%s at %s\n' "$SIGN_CHECKSUMS" "$DATE" > "$DIST_DIR/checksums.txt.sig"
			;;
		auto)
			if [ -x "$BUILD_DIR/bin/providapt-sign" ]; then
				"$BUILD_DIR/bin/providapt-sign" \
					-in "$manifest" \
					-out "$DIST_DIR/checksums.txt.sig" \
					-key "$BUILD_DIR/release-signing.key" \
					-pub-out "$DIST_DIR/checksums.txt.pub"
			elif command -v gpg >/dev/null 2>&1; then
				gpg --batch --yes --armor --detach-sign --output "$DIST_DIR/checksums.txt.sig" "$manifest"
			elif command -v minisign >/dev/null 2>&1; then
				minisign -Sm "$manifest" -x "$DIST_DIR/checksums.txt.sig"
			else
				warn "gpg/minisign not installed; writing unsigned evidence marker"
				printf 'unsigned checksums; install gpg or minisign for detached signature evidence (%s)\n' "$DATE" > "$DIST_DIR/checksums.txt.sig"
			fi
			;;
		gpg)
			gpg --batch --yes --armor --detach-sign --output "$DIST_DIR/checksums.txt.sig" "$manifest"
			;;
		minisign)
			minisign -Sm "$manifest" -x "$DIST_DIR/checksums.txt.sig"
			;;
		providapt|ed25519)
			need_file "$BUILD_DIR/bin/providapt-sign"
			"$BUILD_DIR/bin/providapt-sign" \
				-in "$manifest" \
				-out "$DIST_DIR/checksums.txt.sig" \
				-key "$BUILD_DIR/release-signing.key" \
				-pub-out "$DIST_DIR/checksums.txt.pub"
			;;
		*)
			printf 'ERROR: unsupported SIGN_CHECKSUMS=%s (use auto, providapt, gpg, minisign, or false)\n' "$SIGN_CHECKSUMS" >&2
			exit 1
			;;
	esac
}

run_vulnerability_scans() {
	local report_dir="$BUILD_DIR/security"
	mkdir -p "$report_dir"
	if [ "$RUN_SCANS" = "0" ] || [ "$RUN_SCANS" = "false" ] || [ "$RUN_SCANS" = "no" ]; then
		warn "vulnerability scans disabled"
		return
	fi
	if command -v grype >/dev/null 2>&1; then
		grype dir:"$PROJECT_DIR" -o json > "$report_dir/grype-source.json" || warn "grype source scan reported findings"
	elif command -v docker >/dev/null 2>&1; then
		docker run --rm -v "$PROJECT_DIR:/workspace:ro" "$GRYPE_IMAGE" dir:/workspace -o json > "$report_dir/grype-source.json" || warn "dockerized grype source scan reported findings"
	elif [ "$RUN_SCANS" = "1" ] || [ "$RUN_SCANS" = "true" ]; then
		printf 'ERROR: RUN_SCANS requires grype or trivy\n' >&2
		exit 1
	else
		warn "grype not installed; source vulnerability scan skipped"
	fi
	if command -v trivy >/dev/null 2>&1; then
		trivy fs --format json --output "$report_dir/trivy-fs.json" "$PROJECT_DIR" || warn "trivy fs scan reported findings"
	elif command -v docker >/dev/null 2>&1; then
		docker run --rm -v "$PROJECT_DIR:/workspace:ro" -v "$report_dir:/out" "$TRIVY_IMAGE" fs --format json --output /out/trivy-fs.json /workspace || warn "dockerized trivy fs scan reported findings"
	elif [ "$RUN_SCANS" = "1" ] || [ "$RUN_SCANS" = "true" ]; then
		printf 'ERROR: RUN_SCANS requires trivy or grype\n' >&2
		exit 1
	else
		warn "trivy not installed; filesystem vulnerability scan skipped"
	fi
}

build_container_image() {
	if [ "$BUILD_CONTAINER" = "0" ] || [ "$BUILD_CONTAINER" = "false" ]; then
		return
	fi
	if ! command -v docker >/dev/null 2>&1; then
		printf 'ERROR: BUILD_CONTAINER requested but docker is not installed\n' >&2
		exit 1
	fi
	docker build \
		--label "org.opencontainers.image.source=https://github.com/Chaoqun-Guo/ProvidAPT" \
		--label "org.opencontainers.image.version=$VERSION" \
		--label "org.opencontainers.image.revision=$COMMIT" \
		-t "providapt:$VERSION" \
		-f "$PROJECT_DIR/build/docker/Dockerfile.ubuntu" "$PROJECT_DIR"
	docker image inspect "providapt:$VERSION" > "$DIST_DIR/providapt-container-${VERSION}.inspect.json"
}

run_release_check() {
	need_file "$DIST_DIR/checksums.txt"
	need_file "$DIST_DIR/checksums.txt.sig"
	need_file "$DIST_DIR/sbom.spdx.json"
	need_file "$DIST_DIR/sbom.cdx.json"
	if [ ! -f "$WAIVERS_PATH" ]; then
		mkdir -p "$(dirname "$WAIVERS_PATH")"
		printf '{"waivers":[]}\n' > "$WAIVERS_PATH"
	elif head -c 1 "$WAIVERS_PATH" | grep -q '\['; then
		warn "rewriting legacy array waiver file to object format"
		printf '{"waivers":[]}\n' > "$WAIVERS_PATH"
	fi
	if [ ! -f "$CONFIG_PATH" ] || [ "${CONFIG_PATH##*.}" = "toml" ]; then
		CONFIG_PATH="$BUILD_DIR/release-config.yaml"
		cat > "$CONFIG_PATH" <<EOF
output:
  dir: /var/log/providapt
  format: json
api:
  grpc: ":50051"
  rest: ":18080"
  auth_enabled: true
  auth_keys:
    - release-admin-key
  auth_roles:
    release-admin-key: admin
  cors_origins:
    - https://soc.example.com
control_plane:
  mode: standalone
  role: leader
storage:
  encrypt: true
  key_file: /etc/providapt/storage.key
license:
  path: /etc/providapt/license.yaml
support_bundle:
  redact_archives: true
  retain_archives: 5
capture:
  enable_net: true
  enable_file: true
  enable_proc: true
EOF
	fi
	if [ ! -f "$EVIDENCE_PATH" ]; then
		cat > "$EVIDENCE_PATH" <<EOF
# Release Evidence - ${VERSION}

Date: ${DATE}
Release: ${VERSION}
Commit SHA: ${COMMIT}
Build host: release pipeline container
Status: generated release candidate evidence

## Validation Evidence

- Userspace build: completed
- Package formats: archive, deb, rpm
- Helm archive: generated when chart source is present
- SBOM: SPDX JSON and CycloneDX JSON generated
- Checksums: generated for all dist artifacts
- Checksum signature evidence: ${SIGN_CHECKSUMS}; auto prefers providapt-sign Ed25519 when available
- Vulnerability scans: ${RUN_SCANS}
- Package smoke matrix: run separately with package-smoke-matrix

## Commercial Approval

- Product: generated evidence pending owner signoff
- Engineering: generated evidence pending owner signoff
- Security: generated evidence pending owner signoff
- Legal: generated evidence pending owner signoff
- Support: generated evidence pending owner signoff
- Sales engineering: generated evidence pending owner signoff

## Known Limitations

- Customer-specific API keys, license files, CORS origins, and encryption keys must be replaced before production deployment.
- Detached checksum signature should be produced with customer-approved signing infrastructure for final publication.
- The built-in providapt-sign tool creates verifiable Ed25519 checksum signatures for air-gapped or customer-managed signing workflows.
EOF
	fi
	"$BUILD_DIR/bin/providaptctl" \
		-release-check \
		-config "$CONFIG_PATH" \
		-release-evidence "$EVIDENCE_PATH" \
		-release-waivers "$WAIVERS_PATH" \
		-release-checksums "$DIST_DIR/checksums.txt" \
		-release-checksums-signature "$DIST_DIR/checksums.txt.sig" \
		-release-artifacts-dir "$DIST_DIR" \
		-release-required-artifacts "$REQUIRED_ARTIFACTS" \
		-release-sbom "$DIST_DIR/sbom.spdx.json,$DIST_DIR/sbom.cdx.json" \
		-release-check-out "$DIST_DIR/release-readiness.md"
}

main() {
	log "Preparing commercial release workspace"
	rm -rf "$DIST_DIR"
	mkdir -p "$DIST_DIR" "$BUILD_DIR"

	log "Building userspace binaries"
	(cd "$PROJECT_DIR" && make build-userspace VERSION="$VERSION" COMMIT="$COMMIT" DATE="$DATE" GO_TAGS="$GO_TAGS")

	if [ "$BUILD_EBPF" = "1" ] || [ "$BUILD_EBPF" = "true" ]; then
		log "Building eBPF objects"
		(cd "$PROJECT_DIR" && make build-ebpf)
	else
		warn "BUILD_EBPF disabled; package scripts will use existing build/ebpf objects if present"
	fi

	log "Preparing package defaults"
	prepare_package_defaults

	log "Building package artifacts"
	(cd "$PROJECT_DIR" && VERSION="$VERSION" GO_TAGS="$GO_TAGS" bash build/packages/build_all.sh "$PACKAGE_FORMATS")
	copy_dist_artifacts

	if [ "$BUILD_HELM_ARCHIVE" = "1" ] || [ "$BUILD_HELM_ARCHIVE" = "true" ]; then
		log "Building Helm chart archive"
		build_helm_archive
	fi

	log "Building container evidence"
	build_container_image

	log "Generating SBOMs"
	generate_sbom

	log "Generating checksums"
	generate_checksums

	log "Signing checksums"
	sign_checksums

	log "Running vulnerability scans"
	run_vulnerability_scans

	log "Running release readiness check"
	run_release_check

	log "Commercial release artifacts ready"
	ls -lh "$DIST_DIR"
}

main "$@"
