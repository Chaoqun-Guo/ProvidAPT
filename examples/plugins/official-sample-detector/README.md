# Official Sample Detector Plugin

This example shows the minimum shape of a distributable ProvidAPT plugin for
open-source users. It is intentionally small: one signed bundle placeholder, one
manifest, explicit permissions, compatibility evidence, and rollback drill
metadata.

## Permissions

- `events:read` allows the detector to inspect normalized telemetry events.
- `alerts:write` allows the detector to emit findings into the alert workflow.

The plugin does not request configuration writes, shell execution, or broad
administrative permissions.

## Distribution

Run:

```bash
make plugin-release-gate \
  PLUGIN_MANIFEST=examples/plugins/official-sample-detector/plugin.json \
  PLUGIN_SIGNATURE=examples/plugins/official-sample-detector/official-sample-detector-1.0.0.bundle.sig
```

The release gate verifies the bundle hash, signature hash, compatibility
evidence, permission model, and rollback drill before catalog inclusion.

## Rollback

Disable this plugin in the ProvidAPT plugin list, restore the previous signed
bundle if one exists, and restart the affected daemon group.
