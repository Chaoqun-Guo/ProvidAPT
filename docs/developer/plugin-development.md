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
