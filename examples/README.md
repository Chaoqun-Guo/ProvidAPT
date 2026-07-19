# Examples

This directory contains practical ProvidAPT examples for local testing, API integration, detection rules, and operator workflows.

## Directory Map

| Directory | Purpose |
| --- | --- |
| `basic-capture/` | Minimal eBPF ring-buffer capture example |
| `client-status/` | Go client example for querying daemon status |
| `supportbundle-api/` | API examples for support bundle export and download |
| `provql/` | Ready-to-use ProvQL investigation queries |
| `rules/` | Detection rule examples for process, file, network, and container activity |
| `api/` | curl, Python, and Go API workflows for status, alerts, trace export, and policy operations |
| `siem/` | Splunk HEC and Elastic Bulk SIEM examples |
| `helm/` | production-oriented Helm values example |
| `deploy/` | Deployment examples for Docker Compose and agent/server topologies |
| `config/` | Local and production configuration templates |

## Recommended Starting Points

- Use `config/providapt.local.toml` for non-production lab evaluation.
- Use `config/providapt.production.yaml` as a hardened production template before injecting customer-specific secrets.
- Use `api/curl-workflows.md` to exercise common operator actions from a shell.
- Use `api/python-client/` or `api/go-client/` for programmatic integration starters.
- Use `rules/` as a starting point for customer-specific detections.
- Use `siem/` to configure Splunk or Elastic delivery in a lab.
- Use `helm/values-production.yaml` as the starting point for Kubernetes values.
- Use `deploy/docker-compose-postgres/` for a PostgreSQL-backed control-plane lab.
- Use `deploy/agent-server/` for multi-host fleet monitoring examples.

## Safety Notes

- Replace all sample API keys, tokens, TLS paths, and domains before production use.
- Review every rule for customer environment fit before publishing.
- Do not run production agents with local evaluation secrets.
