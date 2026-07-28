# License Activation Server

ProvidAPT includes a small Docker-ready activation service for controlled evaluations and commercial deployment staging. It issues signed licenses, publishes license revocation IDs, and exposes the latest upgrade manifest consumed by the dashboard.

## Build and Start

```bash
make build-auth-server
docker compose up -d auth-server
```

The root `docker-compose.yml` starts the service on `http://127.0.0.1:19090` and wires ProvidAPT to:

- `POST /v1/activate` for online activation.
- `GET /v1/revocations` for license revocation checks.
- `GET /v1/releases/latest` for upgrade discovery.

## Configuration

Set these environment variables in Compose, Docker secrets, or the production secret manager:

```bash
PROVIDAPT_AUTH_ADDR=:19090
PROVIDAPT_AUTH_ARTIFACT_DIR=/var/lib/providapt-auth/artifacts
PROVIDAPT_AUTH_LICENSE_SIGNING_KEY=<shared-license-signing-key>
PROVIDAPT_AUTH_ACTIVATION_CODE=<optional-customer-code>
PROVIDAPT_AUTH_API_KEY=<optional-bearer-token>
PROVIDAPT_AUTH_CUSTOMER='Example Customer'
PROVIDAPT_AUTH_EDITION=enterprise
PROVIDAPT_AUTH_MAX_AGENTS=100
PROVIDAPT_AUTH_VALID_DAYS=365
PROVIDAPT_AUTH_RELEASE_VERSION=v1.2.3
PROVIDAPT_AUTH_UPGRADE_DOWNLOAD_URL=https://downloads.example/providapt.tar.gz
PROVIDAPT_AUTH_UPGRADE_SHA256=<artifact-sha256>
PROVIDAPT_AUTH_UPGRADE_SIGNATURE_URL=https://downloads.example/providapt.tar.gz.sig
PROVIDAPT_AUTH_REVOKED_IDS=lic-001,lic-002
```

Place upgrade artifacts under `PROVIDAPT_AUTH_ARTIFACT_DIR`; the server exposes them under `/artifacts/`. For example, `/var/lib/providapt-auth/artifacts/providapt.tar.gz` is reachable as `http://127.0.0.1:19090/artifacts/providapt.tar.gz`.

ProvidAPT agents read these client-side settings:

```bash
PROVIDAPT_LICENSE_ACTIVATION_URL=http://127.0.0.1:19090/v1/activate
PROVIDAPT_LICENSE_REVOCATION_URL=http://127.0.0.1:19090/v1/revocations
PROVIDAPT_UPGRADE_MANIFEST_URL=http://127.0.0.1:19090/v1/releases/latest
```

## Dashboard Workflow

1. Open the dashboard and select **Activation** in the compact header.
2. Click **Activate Online**, enter the activation server URL, and enter the optional activation code.
3. Verify the license state, customer, edition, seats, expiry, fingerprint binding, and signature status.
4. Select **Version** and click **Discover** to load the upgrade manifest.
5. Run **Preflight**, then **Download**, **Apply**, or **Rollback** according to the approved rollout plan.

For production, protect the activation server behind TLS, set `PROVIDAPT_AUTH_API_KEY`, rotate signing keys through the secret backend, and archive activation/upgrade audit records with the release evidence bundle.
