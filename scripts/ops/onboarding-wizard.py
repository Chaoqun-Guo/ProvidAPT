#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "providapt.onboarding_bundle.v1"


def config_yaml(args: argparse.Namespace) -> str:
    state_backend = args.postgres_dsn if args.postgres_dsn else "/var/log/providapt/control-plane-state.json"
    return f"""output:
  dir: {args.log_dir}
  format: json
  max_file_bytes: 16777216
  retain_max_bytes: {args.log_retain_bytes}
  alert_max_file_bytes: 8388608
  alert_retain_max_bytes: {args.alert_retain_bytes}
api:
  grpc: ":{args.grpc_port}"
  rest: ":{args.rest_port}"
  auth_enabled: true
  auth_keys:
    - ${{PROVIDAPT_API_AUTH_KEYS}}
  auth_roles:
    ${{PROVIDAPT_API_AUTH_KEYS}}: admin
control_plane:
  mode: {args.mode}
  role: leader
  state_backend: {state_backend}
storage:
  encrypt: true
  key_file: /etc/providapt/storage.key
policy:
  enabled: true
  endpoint: http://127.0.0.1:{args.rest_port}
  api_key: ${{PROVIDAPT_POLICY_API_KEY}}
  poll_interval: 30s
support_bundle:
  redact_archives: true
  retain_archives: 5
capture:
  enable_net: true
  enable_file: true
  enable_proc: true
"""


def build_bundle(args: argparse.Namespace) -> dict[str, object]:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    config_path = out_dir / "providapt.onboarding.yaml"
    checklist_path = out_dir / "onboarding-checklist.md"
    manifest_path = out_dir / "onboarding-manifest.json"
    config_path.write_text(config_yaml(args), encoding="utf-8")
    checklist = f"""# ProvidAPT First-Run Onboarding Checklist

- Confirm Linux kernel supports selected attachment mode.
- Fill and validate secrets with `make ops-secret-template` and `make ops-secret-validate`.
- Install TLS certificates or run `make ops-tls-bootstrap` for lab bootstrap.
- Start PostgreSQL when `postgres_dsn` is configured.
- Start server on REST port `{args.rest_port}` and gRPC port `{args.grpc_port}`.
- Open dashboard and confirm all agents report healthy.
- Run `make enterprise-readiness` before customer handoff.
"""
    checklist_path.write_text(checklist, encoding="utf-8")
    manifest = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "mode": args.mode,
        "rest_port": args.rest_port,
        "grpc_port": args.grpc_port,
        "postgres": bool(args.postgres_dsn),
        "outputs": {
            "config": str(config_path),
            "checklist": str(checklist_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate first-run ProvidAPT onboarding config and checklist.")
    parser.add_argument("--out-dir", default="build/onboarding")
    parser.add_argument("--mode", choices=["standalone", "cluster"], default="standalone")
    parser.add_argument("--rest-port", type=int, default=18080)
    parser.add_argument("--grpc-port", type=int, default=50051)
    parser.add_argument("--log-dir", default="/var/log/providapt")
    parser.add_argument("--log-retain-bytes", type=int, default=268435456)
    parser.add_argument("--alert-retain-bytes", type=int, default=67108864)
    parser.add_argument("--postgres-dsn", default="")
    args = parser.parse_args()
    manifest = build_bundle(args)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
