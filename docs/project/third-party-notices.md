# Third-Party Notices

This document tracks third-party notice obligations for open-source delivery. It is a release-review companion to generated SBOM artifacts.

## Sources of Truth

- `dist/sbom.spdx.json`
- `dist/sbom.cdx.json`
- Go module metadata in `go.mod` and `go.sum`
- container base image package manifests when container artifacts are shipped

## Release Checklist

| Check | Status |
| --- | --- |
| SPDX SBOM generated | required before publication |
| CycloneDX SBOM generated | required before publication |
| direct Go module licenses reviewed | required before publication |
| container base image notices reviewed when shipped | required for container artifacts |
| third-party notices packaged or linked in handoff | required before operator handoff |

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

Do not publish final release artifacts until Legal has approved the generated SBOMs and required notices.
