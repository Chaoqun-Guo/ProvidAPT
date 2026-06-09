# Contributing to ProvidAPT

## Code Organization

ProvidAPT uses a single Go module with capability-based package boundaries:

- `cmd/` - executable entry points
- `internal/engine/` - event collection, graph construction, analysis, loader logic
- `internal/policy/` - alerting, response, supply-chain, self-heal, management logic
- `internal/storage/` - cache, schema, Pebble-backed storage, export paths
- `internal/stitcher/` - multi-host graph stitching and distributed analysis
- `pkg/` - reusable public packages such as API, config, notify, support bundle, telemetry

Avoid introducing version-namespaced directories. Extend the current package tree unless a new bounded context is required.

## Development Workflow

1. Fork the repository
2. Create a feature branch from `main`
3. Make focused changes
4. Add or update tests
5. Run local validation
6. Open a pull request with context and test results

## Core Commands

```bash
# Build
make build-core
make build-ebpf
make build-userspace

# Test
make test-core
make ext-test
make cluster-test

# Quality
make fmt
make vet
```

## Coding Standards

- **Go**: follow Go Code Review Comments and run `gofmt`
- **eBPF C**: compile with `clang -target bpf -Wall -Werror`
- **Documentation**: update the relevant page in `docs/`
- **Tests**: cover new behavior with unit tests, and add integration coverage when appropriate

## Pull Request Guidelines

1. Keep the change set focused
2. Include validation steps in the PR description
3. Update user-facing or developer-facing docs when behavior changes
4. Preserve backward compatibility unless the change explicitly removes deprecated behavior
5. Reference related issues or operational context

## Commit Messages

Use concise conventional messages such as:

- `feat(api): add fleet overview endpoint`
- `fix(loader): handle missing precompiled ebpf objects`
- `docs(project): normalize release documentation`
- `test(ticketing): cover servicenow comment updates`

## Review Focus

Reviewers should check:

- correctness and safety
- test coverage
- performance implications
- security impact
- documentation completeness

## Getting Help

- Open an issue for bugs or feature requests
- Start a discussion for design or usage questions
