# Visualization and Analysis Guide

This guide explains how to read ProvidAPT dashboard views, provenance traces,
and exported investigation evidence.

## Node Types

| Node Type | Color | Meaning |
| --- | --- | --- |
| Process | Blue | Executing process or process lineage |
| File | Green | File, directory, or memory-backed file entity |
| Network | Red / orange | IP, port, socket, or remote endpoint |
| Memory | Purple | Memory event such as anonymous executable memory |
| Pipe | Gray | Inter-process pipe or IPC relation |
| Package | Teal | Software package or SBOM-bound artifact |
| Credential | Yellow | Security context, identity, or credential-sensitive object |

## Edge Semantics

| Relation | Direction | Meaning |
| --- | --- | --- |
| `prov:used` | process -> entity | Process read, opened, connected to, or used an entity |
| `prov:wasGeneratedBy` | entity -> process | Entity was created or written by a process |
| `prov:wasInformedBy` | child -> parent | Process fork, exec, IPC, or causal notification |
| `prov:wasDerivedFrom` | derived -> source | Data was copied, transformed, archived, or staged |
| `prov:hadSecurityContext` | node -> context | Node is associated with an identity or security context |

Trace SVG exports render causal direction as `source -> target`. Dashed edges are
retained cross-links that preserve important relationships without forcing every
edge into the main tree.

## Large Trace Readability

Trace SVG exports use a left-to-right tree layout. For dense traces, nodes with
the same graph depth and node type may be folded into a dashed purple cluster
box. A cluster is not a separate event. It is a readability summary for nodes
that would otherwise create a long vertical list at the same stage of the trace.

Folded boxes show:

- node type and graph depth
- number of folded nodes
- fold reason
- short member preview
- full member list in the SVG `<title>` tooltip

In the Trace Viewer, use `Clusters` to highlight folded groups. Use search to
match cluster member IDs, paths, commands, or event labels. Select a node, edge,
or folded cluster to open a structured details panel with source, target,
relation, event, command line, path, and fold metadata where available.

The raw SVG endpoint accepts `layout=tree`, `layout=compact`,
`layout=timeline`, or `layout=grouped`. The viewer can switch between the same
layout modes after load and recalculates visible edge paths for the selected
view.

This keeps process, file, and network structure readable while preserving the
event table for detailed relation review.

## Operation Colors

| Color | Operation |
| --- | --- |
| Blue | read / use |
| Green | write / create |
| Yellow | exec / fork |
| Red | network |
| Purple | derived data |
| Gray dashed | security context or folded summary |

## Event Structure Table

The SVG includes an `Event Structure` table below the graph. Events are grouped
by analyst category:

- execution / process activity
- discovery or credential access / file reads
- persistence or collection / file writes
- command and control / network
- data derivation
- security context
- other provenance relations

Only the first few relations in each category are expanded. Additional relations
are counted as collapsed rows to avoid very long pages.

## Investigation Workflow

1. Open `Trace SVG` from Alert Workflow or a ground-truth record.
2. Read the title and focused scope at the top of the SVG.
3. Follow tree edges from left to right.
4. Use edge colors to distinguish file, process, network, and derived-data operations.
5. Review dashed cross-links for non-tree causal context.
6. Use the event table to inspect detailed attributes such as command line, path, PID, UID, and endpoint.
7. Download the Markdown investigation report for incident handoff.

## Export Formats

| Format | Extension | Use Case |
| --- | --- | --- |
| PROV-JSON | `.json` | Machine analysis and custom tooling |
| GraphML | `.graphml` | yEd, Gephi, or offline graph exploration |
| SVG | `.svg` | Browser review, tickets, and report evidence |
| PNG | `.png` | Visual regression baselines and ticket attachments |
| Markdown report | `.md` | Incident handoff and analyst notes |
| JSON report | `.json` | Automation and downstream case systems |
| Markdown | `.md` | Analyst handoff and incident review |

Example:

```bash
curl -s http://<server>:18080/api/v1/graph/export > graph.json
curl -s "http://<server>:18080/api/v1/investigation/report?node=p:1234&direction=backward&format=markdown" \
  > investigation.md
```
