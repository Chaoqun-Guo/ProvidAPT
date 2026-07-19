# Third-Party Notices

This document tracks third-party notice obligations for commercial delivery. It is a release-review companion to generated SBOM artifacts.

## Sources of Truth

- `dist/sbom.spdx.json`
- `dist/sbom.cdx.json`
- Go module metadata in `go.mod` and `go.sum`
- container base image package manifests when container artifacts are shipped

## Release Checklist

| Check | Status |
| --- | --- |
| SPDX SBOM generated | pending |
| CycloneDX SBOM generated | pending |
| direct Go module licenses reviewed | pending |
| container base image notices reviewed when shipped | pending |
| third-party notices packaged or linked in handoff | pending |

## Notice Template

For each dependency requiring attribution:

```text
Component: <name>
Version: <version>
License: <license>
Source: <source URL>
Notice: <required notice text or link>
```

## Publication Rule

Do not publish final commercial artifacts until Legal has approved the generated SBOMs and required notices.
