# Package Build Notes

ProvidAPT source-controlled installation assets live under `deploy/linux/`:

- `deploy/linux/providapt.service`
- `deploy/linux/providapt.env`
- `scripts/install/install-linux.sh`
- `scripts/install/uninstall-linux.sh`
- `scripts/upgrade/preflight-linux.sh`

Release package builders should include these files in `.deb`, `.rpm`, and `.tar.gz` artifacts and preserve locally modified files as configuration:

- `/etc/providapt/providapt.toml`
- `/etc/default/providapt`

Minimum package lifecycle hooks:

1. Create the `providapt` system user if it does not exist.
2. Create `/var/lib/providapt`, `/var/log/providapt`, and `/usr/local/lib/providapt/ebpf`.
3. Install `providapt.service` to the systemd unit directory.
4. Run `systemctl daemon-reload`.
5. Enable the service, but only auto-start it when the package/channel explicitly promises auto-start.
6. Stop the service before uninstalling binaries.
7. Keep configuration and state by default; require an explicit purge action to remove them.

Before publishing a package, run:

```bash
python scripts/verify-utf8.py
sudo scripts/upgrade/preflight-linux.sh
sudo START_SERVICE=0 scripts/install/install-linux.sh
sudo scripts/install/uninstall-linux.sh
```
