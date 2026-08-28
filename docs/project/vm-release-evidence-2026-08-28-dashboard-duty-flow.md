# VM Dashboard Duty Flow Evidence - 2026-08-28

This evidence records the VM-validated Dashboard duty-flow simplification and
browser screenshot baseline for the open-source build.

## Scope

- Commit: `30cddab5d48ae79c5d080ef734f49fe98810d79e`
- Version string: `v1.2.2-305-g30cddab`
- Environment: three-node VM fleet over private overlay networking
- Build type: open-source control plane, no API key or activation workflow
- Evidence captured at: `2026-08-28T02:20:34Z`

## VM Deployment Checks

| Check | Result |
| --- | --- |
| Three-node deployment | `pass` |
| Healthy agents | `3/3` |
| Expected commit | `30cddab` |
| Open-source residue gate | `pass` |
| Residue failures | `0` |

## Browser Baseline

The baseline used real browser rendering against the VM-served Dashboard and a
real VM graph trace. Raw screenshots and temporary manifests were used only for
the run workspace and are not committed because they can contain live operator
state.

| Page | Viewport | Status | SHA-256 | Bytes |
| --- | --- | --- | --- | ---: |
| `dashboard` | `390x844` | `captured` | `c13ce780b52528dd6764e574ef17d89bb330b8cafbf968337b90bf762dc4f918` | 264564 |
| `dashboard` | `1366x768` | `captured` | `7734e62111145a6f511d4f899a97789ac2d109c8c6711b6243dccd2aa1643eb7` | 364150 |
| `dashboard` | `1920x1080` | `captured` | `7572cedd54554a30d8ead4a68b1b574b804a5952767825b8b049e417d381f170` | 393458 |
| `dashboard` | `2560x1080` | `captured` | `9d686972b44fc3a4345e3a7324d8d1df0c91e5e5720d268b7cb7eacfd46b7975` | 426982 |
| `trace-viewer` | `390x844` | `captured` | `f1208ea86ab00d94dcb4a321e77135b37c13c09e600f2b8222c02748ff6d60df` | 136448 |
| `trace-viewer` | `1366x768` | `captured` | `782402d22ff66a58452543651173946219c202d12f1b1e211082c90467a382e4` | 180793 |
| `trace-viewer` | `1920x1080` | `captured` | `c800cc1b4fed07191512a82c94666e30c71c2d1be5cb17f05f9322593797cb12` | 247116 |
| `trace-viewer` | `2560x1080` | `captured` | `835269291c2ac941096ac3042c13b6919c9986d143086c972c693c258a220d46` | 285803 |

## Visual Gate Summary

| Area | Result |
| --- | --- |
| Visual regression gate | `pass` |
| Screenshot coverage | `8/8` |
| Complete default matrix | `true` |
| Missing required screenshots | `0` |
| DOM assertion failures | `0` |
| Dashboard horizontal overflow | `0px` on all captured viewports |
| Dashboard element overflow | `0px` on all captured viewports |
| Dashboard text overflow | `0px` on all captured viewports |
| Trace Viewer SVG readiness | `pass` on all captured viewports |

## Notes

- Dashboard navigation was simplified around the operator path:
  `Today -> Triage -> Trace -> Act`.
- Low-frequency release and operations evidence remain in secondary workspaces.
- Final release artifacts and security scans still need to be regenerated after
  the final release tag is created.
