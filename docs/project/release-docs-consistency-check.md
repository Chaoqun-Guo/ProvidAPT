# Release Docs Consistency Check

Date: 2026-06-09
Release: `v1.2.2`

## Scope Checked

- `README.md`
- `CHANGELOG.md`
- `docs/developer/INDEX.md`
- `docs/developer/changelog.md`
- `docs/developer/release-notes-v1.2.2.md`
- `docs/developer/release-readiness.md`
- `docs/project/documentation-audit.md`
- `docs/project/release-evidence-v1.2.2.md`
- `docs/project/project-layout.md`
- `DEVELOPMENT_PROGRESS.md`
- `COMMERCIALIZATION_ROADMAP.md`
- `.github/workflows/release.yml`

## Verified Alignment

- Release identifier is consistently `v1.2.2`
- Build/test command references use `build-core`, `build-ebpf`, `build-userspace`, `install-local`, and `test-core`
- Deployment defaults and installer examples align with `v1.2.2`
- Release notes, changelog, and workflow files describe the same release train

## Open Editorial Notes

- Historical engineering logs remain in `DEVELOPMENT_PROGRESS.md` and `COMMERCIALIZATION_ROADMAP.md`; they are kept for traceability, not as operator-facing product docs
- Some generated files may still contain generated comments that are not part of end-user documentation
