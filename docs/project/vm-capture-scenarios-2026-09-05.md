# VM Capture Scenarios - 2026-09-05

This note records the first live run of the low-noise VM capture scenario runner. It is a public-safe summary only; raw command output and VM-specific evidence remain in ignored local `build/` paths.

## Scope

The runner exercises five behaviors that are easy for operators to reproduce before collecting NDJSON field evidence:

| Scenario | Purpose |
| --- | --- |
| `shell_activity` | Trigger an explicit shell command path. |
| `file_mutation` | Create, rename, and delete a temporary file. |
| `network_activity` | Call the ProvidAPT status API over the lab network. |
| `process_chain` | Spawn a nested child process. |
| `permission_change` | Change temporary file mode bits with `chmod`. |

## Live Result

Command shape:

```sh
make vm-capture-scenarios PROVIDAPT_VM_HOSTS="..." PROVIDAPT_SERVER_URL=http://vm-ubuntu-master:18080 OUT_DIR=build/vm-capture-scenarios-live
```

Result:

| Area | Status |
| --- | --- |
| VM hosts exercised | `3` |
| `shell_activity` | `pass` on all hosts |
| `file_mutation` | `pass` on all hosts |
| `network_activity` | `pass` on all hosts |
| `process_chain` | `pass` on all hosts |
| `permission_change` | `pass` on all hosts |
| Overall runner status | `pass` |

## Operator Flow

Use this runner before the capture/enrichment gate when validating a fresh deployment:

```sh
make vm-capture-scenarios PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master ubuntu@vm-ubuntu-slave centos@vm-centos-slave"
make collect-vm-capture-evidence PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-master ubuntu@vm-ubuntu-slave centos@vm-centos-slave"
make vm-daily-evidence-summary CAPTURE_SCENARIOS=build/vm-capture-scenarios/vm-capture-scenarios.json CAPTURE_ENRICHMENT_GATE=build/vm-capture-evidence/capture-enrichment-field-gate.json
```

## Remaining Gap

The runner proves that the VM hosts executed the expected behavior scenarios. The next improvement is to correlate each scenario marker back to captured NDJSON events so the final evidence can prove both scenario execution and collector observation in one report.
