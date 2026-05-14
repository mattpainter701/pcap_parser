# PCAP Parser — Project Spec

## Purpose
Build a fast, reliable network capture analysis tool that reads PCAP files, identifies devices and conversations, and exports useful reports for investigation and visualization.

## Product vision
The tool should be good at three things:
- extracting accurate device and conversation data
- producing clean outputs that are easy to visualize or ingest
- doing the work quickly enough to handle real captures without feeling sluggish

## Current direction
Continue building out the pcap parser with an explicit eye toward performance. Python remains the baseline implementation, but a Rust reimplementation or Rust-assisted hot path should be considered if it materially improves speed, memory use, or throughput.

## Non-goals
- Not a packet sniffer for live traffic capture
- Not a full SIEM replacement
- Not a generic network dashboard
- Not a UI-first product with weak parsing fidelity

## Core outputs
The parser should generate:
- device inventory data
- MAC/vendor resolution
- IP-to-device mappings
- TCP/UDP port inventories
- bidirectional conversation summaries
- traffic volume statistics
- VLAN / DiffServ / protocol metadata
- CSV and JSON outputs suitable for downstream analysis

## Primary use cases
- understand what devices are present in a capture
- identify who talked to whom
- summarize traffic patterns quickly
- feed graph / topology tools
- support investigation and visualization workflows

## Milestones
### Milestone A — Stabilize the current parser
- Keep Python parser behavior correct and predictable
- Tighten output schema and naming consistency
- Improve CLI ergonomics and error handling
- Preserve compatibility with existing sample captures and outputs

### Milestone B — Improve performance
- Profile current bottlenecks
- Reduce repeated packet processing work
- Improve memory use on larger PCAPs
- Make output generation faster for large captures

### Milestone C — Evaluate Rust
- Decide whether Rust should be a full rewrite, a parser core, or a sidecar component
- Benchmark Rust vs Python on realistic captures
- Keep correctness and output parity as the main requirement
- Only migrate if the gain is real and maintainable

### Milestone D — Better analysis output
- Improve conversation classification
- Improve vendor / service enrichment
- Improve report clarity for humans and machines
- Make JSON output more topology-friendly

## Acceptance criteria
A release is good when:
- it parses representative PCAPs without manual cleanup
- the outputs are consistent and well-structured
- device and conversation results are explainable
- performance is acceptable on larger captures
- any Rust work preserves or improves correctness and maintainability

## Architecture direction
### Python baseline
Keep the current Python parser as the reference implementation until a faster path is proven.

### Rust evaluation criteria
If Rust is introduced, it should be used for:
- the most expensive parsing/aggregation hot paths
- safer and faster binary parsing
- reusable library logic with strong test coverage

Rust is worth it only if it can clearly improve:
- speed on large captures
- memory behavior
- long-term maintainability of the parser core

## Development setup
- Python 3.x environment
- PyShark / packet parsing dependencies
- IEEE OUI data for vendor lookup
- sample PCAP files for regression checks

## Validation
Use the Docker dev/test server for:
- parser regression tests on sample PCAPs
- output diffing against known-good CSV / JSON files
- performance tests on larger captures
- Rust prototype benchmarking if introduced

Validation should answer:
- does the parser still produce correct results?
- are outputs stable across changes?
- is it faster or lighter than before?
- does any new code preserve device / conversation accuracy?

## Priorities
1. Keep parser behavior correct and trustworthy
2. Improve performance on real PCAP sizes
3. Tighten and standardize outputs
4. Benchmark Rust as a serious option, not a novelty
5. Keep the tool easy to run and inspect

## Success definition
This project is successful when a user can point it at a capture and get accurate, useful device and conversation intelligence quickly enough to support real analysis work.
