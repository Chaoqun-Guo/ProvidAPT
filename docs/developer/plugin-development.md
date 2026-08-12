# Plugin Development Guide

ProvidAPT supports a plugin system for extending detection, scoring, and threat intelligence capabilities.

## Plugin Interface

All plugins must implement the `Plugin` interface:

```go
type Plugin interface {
    // Analyse is called with the current provenance graph snapshot.
    // Returns a list of findings discovered during analysis.
    Analyse(snap *provenance.Graph) []*Finding
}
```

Optionally implement `LifecyclePlugin` for setup/teardown:

```go
type LifecyclePlugin interface {
    Init(config map[string]interface{}) error
    Shutdown() error
}
```

## Plugin Types

### Detection Plugins
Analyze the provenance graph for suspicious patterns. See `pkg/plugin/sigma/` for a Sigma rule example.

### Scoring Plugins
Assign risk scores to detected events. See `pkg/plugin/scoring/` for the scoring framework.

### Threat Intelligence Plugins
Match IOCs (IPs, domains, hashes) against the graph. See `pkg/plugin/threatintel/` for reference.

## Registering a Plugin

### Compile-Time Registration (Recommended)

```go
package myplugin

import "github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"

func init() {
    plugin.Register("my-plugin", &MyPlugin{})
}

type MyPlugin struct{}

func (p *MyPlugin) Analyse(snap *provenance.Graph) []*plugin.Finding {
    // Your detection logic here
    return nil
}
```

### Configuration

Enable plugins in `providapt.toml`:

```toml
[plugins]
enabled = ["my-plugin", "sigma", "threatintel"]
```

## Finding Structure

```go
type Finding struct {
    PluginName string            `json:"plugin"`
    RuleID     string            `json:"rule_id"`
    Title      string            `json:"title"`
    Severity   string            `json:"severity"` // critical, high, medium, low, info
    Score      float64           `json:"score"`
    Nodes      []string          `json:"nodes"`
    Edges      []string          `json:"edges"`
    Metadata   map[string]string `json:"metadata,omitempty"`
}
```

## Testing

Plugins are tested with standard Go unit tests. See `pkg/plugin/*_test.go` for examples.

## Release Gate

Before distributing a plugin, run the release gate against its manifest and
signature evidence:

```bash
make plugin-release-gate \
  PLUGIN_MANIFEST=plugins/example/plugin.json \
  PLUGIN_SIGNATURE=plugins/example/plugin.json.sig \
  OUT_DIR=build/plugins/example
```

An open-source-safe fixture is available for local release evidence smoke tests:

```bash
make plugin-example-gates
```

It validates `examples/plugins/sample-detector/plugin.json`, verifies the sample
artifact SHA-256, and aggregates the result through the catalog gate. The
included `.sig` file is a public fixture only; production plugin releases must
replace it with the organization's approved signing workflow.

The manifest must include the following fields:

```json
{
  "name": "example-detector",
  "version": "1.0.0",
  "type": "detection",
  "providapt_min_version": "1.2.0",
  "providapt_max_version": "1.3.0",
  "entrypoint": "example-detector.so",
  "permissions": [
    "events:read",
    "alerts:write"
  ],
  "distribution": {
    "channel": "signed-bundle",
    "artifact": "example-detector-1.0.0.tar.gz",
    "signature_algorithm": "ed25519",
    "artifact_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "compatibility_tests": [
    {
      "providapt_version": "1.2.0",
      "status": "pass"
    }
  ],
  "rollback": [
    "disable example-detector in providapt.toml",
    "restore the previous signed plugin bundle",
    "restart providaptd"
  ],
  "rollback_drill": {
    "status": "pass",
    "tested_at": "2026-08-12T00:00:00Z",
    "tested_by": "release-operator",
    "steps_verified": 3
  }
}
```

Supported plugin types are `detection`, `scoring`, `threatintel`, and
`enrichment`. Versions must use semantic versioning, for example `1.0.0`.
Distributed plugins must declare least-privilege permissions in `scope:action`
form, a signed artifact distribution policy, a SHA-256 digest for the artifact,
at least one passing compatibility test, concrete rollback instructions, and a
passing rollback drill that covers every rollback step. Supported signature
algorithms are `ed25519`, `cosign`, and `minisign`. The compatibility range uses
`providapt_min_version` and optional `providapt_max_version`; the minimum version
must not be greater than the maximum version.

The gate writes:

| File | Purpose |
| --- | --- |
| `plugin-release-gate.json` | Machine-readable release decision, manifest hash, artifact hash evidence, compatibility tests, distribution policy, rollback drill, and validation findings |
| `plugin-release-gate.md` | Operator-readable checklist for approval and rollback |

Unsigned plugins are blocked by default. For internal development only, use:

```bash
make plugin-release-gate \
  PLUGIN_MANIFEST=plugins/example/plugin.json \
  ALLOW_UNSIGNED_PLUGIN=1
```

Open-source releases should keep plugin manifests, signatures, gate reports, and
rollback instructions with the release evidence bundle.

When shipping more than one plugin, aggregate the individual gate outputs into a
catalog decision:

```bash
make plugin-catalog-gate \
  PLUGIN_GATES="build/plugins/sigma/plugin-release-gate.json build/plugins/intel/plugin-release-gate.json" \
  REQUIRE_PLUGINS=1 \
  REQUIRE_PLUGIN_SIGNATURE=1 \
  REQUIRE_PLUGIN_PERMISSIONS=1
```

The catalog gate blocks duplicate plugin name/version pairs, blocked plugin
release gates, missing signatures, missing permissions, incomplete distribution
metadata, missing artifact SHA-256 evidence, missing compatibility pass evidence,
missing rollback steps, and failed or incomplete rollback drills.
