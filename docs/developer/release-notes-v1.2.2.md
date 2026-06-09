# Release Notes — v1.2.2

Date: 2026-06-09
Status: Released
Version: `v1.2.2`

## Summary

Patch release fixing the `golangci-lint` v2 migration regression and resolving
several CI and workflow compatibility issues identified during the v1.2.1→v1.2.2
release cycle.

## Fixed

- **golangci-lint v2 workflow**: The lint workflow was pinned to `golangci-lint
  v2.0`, which uses the `--fix` flag removed in the v2 API. Upgraded to
  `v2.12.2` to match the actual command-line contract.
- **Go version drift in ci.yml**: The `CI` workflow was running Go `1.22` while
  `lint.yml` and `release.yml` both used `1.25`. Unified to `1.25` across all
  workflows.
- **SBOM action version**: `anchore/sbom-action@v0` uses the old Node 16
  runtime. Upgraded to `@v1` for Node 24 compatibility.
- **Misplaced v1.2.3 tag**: The tag pointed to an ancestor of v1.2.2. Deleted.

## Added

- `.editorconfig` for consistent editor settings across the project
- `.gitattributes` for line-ending normalization and binary-type markers
- `scripts/verify-utf8.py` for automated encoding checks
- `docs/project/encoding-policy.md` documenting project encoding conventions
- `examples/` directory with API client, config, ProvQL, and support-bundle
  walkthroughs
- v1.2.2 entries in `CHANGELOG.md` and `docs/developer/changelog.md`

## Validation

- `golangci-lint v2.12.2` on release-scoped packages: `0 issues`
- `go test ./...` release packages: all pass
- `python scripts/verify-utf8.py`: pass
- Local temp/cache directories cleaned
