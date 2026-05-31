# Contributing to ProvidAPT

## Code Organization

The codebase follows a single Go module layout with version namespaces under `internal/`:

- `internal/engine/v2/` — v2.0 features
- `internal/engine/v21/` — v2.1 features  
- `internal/engine/v22/` — v2.2 features
- `internal/storage/v2/`, `internal/policy/v2/`, etc.

New features should be added in the appropriate version namespace or create a new one.

## Development Workflow

1. Fork the repository
2. Create a feature branch from `main`
3. Make changes following the coding standards
4. Add tests for new functionality
5. Run `make test` to verify
6. Submit a pull request

## Coding Standards

- **Go**: Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and run `go fmt` before committing
- **eBPF C**: Use `clang -target bpf` with `-Wall -Werror`. Keep programs under 4096 BPF instructions
- **Documentation**: Update docs/ when adding or changing features
- **Tests**: New features require unit tests. Integration tests for end-to-end scenarios

## Testing

```bash
# Unit tests
make test

# Version-specific tests
make ext-test
make cluster-test

# Integration tests (requires root + eBPF)
sudo make attack-sim
sudo make verify-capture

# Docker-based testing
make docker-test
```

## Pull Request Guidelines

1. Keep PRs focused on a single concern
2. Include test coverage for new code
3. Update relevant documentation
4. Ensure all existing tests pass
5. Reference related issues in the PR description

## Commit Messages

Follow conventional commits format: `type(scope): description`

- `feat(engine): add new provenance query type`
- `fix(storage): correct batch write race condition`
- `docs(architecture): update data flow diagram`
- `test(stitcher): add cross-host merge test`

## Code Review

All submissions require review. Reviewers should check for:
- Correctness of logic
- Test coverage
- Performance considerations (eBPF instruction count, memory allocation)
- Security implications
- Documentation completeness

## Getting Help

- Open an issue for bugs or feature requests
- Submit a discussion for questions
