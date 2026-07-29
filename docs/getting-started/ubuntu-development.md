# Ubuntu Development

This guide prepares a clean Ubuntu host for ProvidAPT development.

## Supported Baseline

- Ubuntu 22.04 LTS or 24.04 LTS
- Linux kernel 5.8 or later; 5.11 or later is recommended for BPF LSM
- Go 1.25 or later
- BTF available at `/sys/kernel/btf/vmlinux`

## First-Time Setup

```bash
git clone https://github.com/Chaoqun-Guo/ProvidAPT.git
cd ProvidAPT

make verify-env
sudo make install-deps
make verify-env
```

Install Go 1.25 or later from your approved package mirror or from the official
Go distribution if `make verify-env` reports that `go` is missing or too old.

## BPF LSM

Full capture quality requires BPF LSM. Check the active LSM list:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is missing, add it to the kernel command line and reboot:

```bash
sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lsm=bpf,/' /etc/default/grub
sudo update-grub
sudo reboot
```

After reboot:

```bash
make verify-env
```

## Daily Workflow

```bash
make build-userspace
make test-core
make build-ebpf
sudo make loader-smoke
```

Use the full build when kernel headers and BTF are ready:

```bash
make build-core
sudo make install-local
sudo systemctl start providapt.service
```

The local dashboard defaults to:

```text
http://127.0.0.1:18080
```

## Docker Development Shell

Use Docker when you need a repeatable Ubuntu userspace toolchain:

```bash
docker compose run --rm shell
```

The container can build userspace code. Kernel-loader validation still needs a
real Linux host with the required BPF capabilities and mounted kernel
filesystems.

## Repository Hygiene

- Keep generated outputs under `build/bin`, `build/ebpf`, `build/coverage`, or `dist`.
- Do not commit VM logs, NDJSON captures, model datasets, or temporary test output.
- Test-only scratch directories should use `.tmp-*`, which is ignored by Git.
- Keep repository text files in UTF-8 with LF line endings.
