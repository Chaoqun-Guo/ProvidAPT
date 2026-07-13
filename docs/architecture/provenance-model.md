# Provenance Data Model

ProvidAPT models host activity as a directed provenance graph. Nodes represent entities, and edges represent causal relationships between those entities.

## Node Types

| Type | Meaning | Example |
| --- | --- | --- |
| `process` | Process or thread identity | `nginx worker #1234` |
| `file` | File or directory identity | `/etc/passwd` |
| `net` | Network endpoint | `10.0.0.1:443` |
| `ipc` | Inter-process communication endpoint | `pipe:[12345]` |
| `credential` | Credential or privilege transition | `setuid`, `apparmor` |

## Edge Types

| Type | Meaning | Typical Scenario |
| --- | --- | --- |
| `fork` | Process creates another process | Shell starts a child command |
| `execute` | Process executes a binary | `execve` loads an executable |
| `read` | Process reads a file | Reads a configuration or credential file |
| `write` | Process writes a file | Writes a log, dropper, or payload |
| `connect` | Process opens an outbound connection | Command-and-control callback |
| `accept` | Process accepts an inbound connection | Reverse shell listener |
| `send` / `recv` | Process sends or receives network data | Data transfer |

## Detection Example

```text
attacker.sh (exec)
  -> bash (fork)
    -> curl (exec)
      -> connect(c2.attacker.com:443)  [C2 communication]
    -> chmod (exec)
      -> write(/tmp/malware)           [payload staging]
    -> /tmp/malware (exec)
      -> connect(c2.attacker.com:8443) [second stage]
      -> read(/etc/shadow)             [credential access]
```
