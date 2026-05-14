# PCAP Parser — Project Spec v2

## Purpose
Build a fast, reliable network capture analysis tool that reads PCAP files, identifies devices and conversations, and exports structured reports for investigation, visualization, and downstream topology tools. Evolve from a single Python script into a high-performance, well-tested analysis pipeline with an optional Rust acceleration path.

## Product vision
The tool should excel at three things:
- extracting accurate device and conversation data from any PCAP
- producing clean, schema-stable outputs suitable for machine ingestion
- processing large captures quickly enough to support real analysis workflows

The architecture should support Python as the reference implementation and Rust as an optional acceleration layer for hot paths — either partial (Rust core with Python orchestration) or full (complete Rust rewrite).

## Current state
- Single `pcap_parser.py` file (~several thousand lines)
- PyShark-based packet parsing (Wireshark/tshark dependency)
- IEEE OUI database for MAC vendor lookup
- Outputs: device CSV, conversation CSV, network JSON (D3-friendly)
- Supports IPv4, IPv6, VLAN, DiffServ, TCP flags, conversation status detection
- CLI interface with --format, --output, --debug flags

## Technical stack
- Python 3.x + PyShark
- IEEE OUI database (local or downloaded)
- Rust (optional): pcap-rs / pnet for raw packet parsing
- Regression test fixtures: sample PCAPs with known-good outputs
- Docker for validation environment

## Non-goals
- Not a live packet sniffer or real-time monitor
- Not a full SIEM or IDS replacement
- Not a generic network dashboard
- Not a UI-first product with weak parsing fidelity
- Not a Wireshark replacement

---

## Sprint/Epic Roadmap (12 sprints)

### Sprint 1 — Output Schema Stabilization
**Goal:** Lock down canonical JSON and CSV schemas so downstream consumers can depend on stable output.

**Tasks:**
- Define JSON schema for device records: mac, vendor, ip_addresses, tcp_ports, udp_ports, first_seen, last_seen, packet_count, vlan_ids, diffserv_values
- Define JSON schema for conversation records: src_mac, dst_mac, src_ip, dst_ip, protocol, src_port, dst_port, packets_a_to_b, bytes_a_to_b, packets_b_to_a, bytes_b_to_a, status, tcp_flags, vlan_ids, duration_seconds
- Define CSV column specification with header contracts
- Write JSON Schema (draft-07) validation files
- Add --validate-output flag that checks generated output against schema
- Document schema with examples for each field
- Version the schema (v1.0.0) with a migration policy

**Acceptance:** Every run produces output that validates against the schema. Breaking schema changes require a version bump.

### Sprint 2 — Regression Fixture System
**Goal:** A golden-test suite that catches regressions in device/conversation output.

**Tasks:**
- Curate 10+ sample PCAPs covering: small capture (<100 packets), medium capture (1K-10K), large capture (100K+), IPv4-only, IPv6-only, mixed IPv4/IPv6, VLAN-tagged, MPLS-encapsulated, fragmented packets, encrypted/TLS traffic
- Generate and commit golden output files (JSON + CSV) for each fixture
- Build regression test harness: run parser on each fixture, diff against golden
- Add --regression flag or `pytest` suite that runs all fixtures
- Create acceptable-diff threshold for non-deterministic fields (timestamps, packet counts can vary within tolerance)
- Add CI integration: regression tests block merges on GitHub
- Document how to add new fixtures

**Acceptance:** `pytest` runs 10+ fixtures in <30 seconds. Any output change must be intentional.

### Sprint 3 — Performance Profiling & Benchmark Harness
**Goal:** Quantify where the parser spends time and establish baseline metrics.

**Tasks:**
- Build benchmark harness: run parser on standardized PCAP sizes, measure wall-clock time, CPU time, peak memory
- Profile with cProfile / py-spy on small, medium, large captures
- Identify top-10 hot functions (most time spent)
- Identify top memory allocations (PyShark packet object overhead)
- Create benchmark report format: tables and flamegraph output
- Establish baseline metrics: parse rate (packets/sec), memory per 100K packets
- Add --benchmark flag that runs profiled run and outputs report
- Write benchmark results to SPEC.md appendix

**Acceptance:** A `--benchmark` run produces a quantified breakdown of where every CPU cycle goes.

### Sprint 4 — Python Hot Path Optimization
**Goal:** Speed up the Python parser by 2-5x on large captures without changing behavior.

**Tasks:**
- Replace per-packet dict creation with dataclass/slots for device and conversation records
- Batch OUI lookups (single pass over all MACs, not per-packet)
- Optimize port tracking: use set operations instead of list append+dedup
- Implement incremental CSV/JSON writing (stream output, don't hold everything in memory)
- Add packet filtering: skip irrelevant protocols early (ARP, STP, CDP unless flagged)
- Reduce PyShark object materialization: extract only needed fields per packet
- Implement --fast mode that trades some detail for speed (skip conversation detail, just devices)
- Benchmark after each optimization to verify improvement

**Acceptance:** Parser runs at least 2x faster on the benchmark 100K-packet PCAP. All regression tests still pass.

### Sprint 5 — CLI Ergonomics v2
**Goal:** Professional-grade CLI with clear error messages, progress indicators, and batch support.

**Tasks:**
- Add progress bar for large captures (tqdm with packet count estimate)
- Implement --batch mode: process a directory of PCAPs, produce merged or per-file output
- Add --filter flag for BPF-style filters (host, net, port, proto)
- Improve error handling: graceful recovery from corrupt packets, truncated captures
- Add --stats-only mode: output summary stats without full device/conversation detail
- Implement --compare mode: diff two PCAP outputs
- Add --output-dir flag with smart filename generation
- Write man-page quality --help output

**Acceptance:** CLI errors give actionable messages. Batch mode processes directories without manual scripting.

### Sprint 6 — Output Quality & Enrichment
**Goal:** Richer, more useful output — better conversation classification, service identification, and topology-ready data.

**Tasks:**
- Improve conversation classification: client-server detection, protocol fingerprinting, application identification (HTTP, DNS, SMB, SSH, etc.)
- Add well-known service mapping: map ports to service names with confidence scoring
- Implement conversation grouping: aggregate repeated flows between same hosts
- Add traffic pattern classification: bursty, steady, periodic, bulk-transfer
- Improve VLAN-to-device mapping with tagged/untagged awareness
- Add DiffServ interpretation: map DSCP values to service classes (EF, AF, CS, BE)
- Generate topology-friendly link records (device A ↔ device B with protocol, bandwidth estimate)
- Add --enrich flag to pull external data (vendor DB updates, CVE lookups for detected services)

**Acceptance:** Output JSON provides enough context for a graph tool to render a useful topology without additional processing.

### Sprint 7 — Rust Proof-of-Concept
**Goal:** Validate whether Rust acceleration is worth the investment.

**Tasks:**
- Set up Rust project structure (cargo, workspace if needed)
- Implement Rust packet parser using pcap-rs or pnet crate
- Parse PCAP headers, Ethernet, IP, TCP/UDP — extract same fields as Python parser
- Implement Rust OUI lookup (preload IEEE DB into HashMap)
- Build Python-Rust bridge via PyO3 or ctypes
- Create benchmark harness: Rust parser vs Python parser on same PCAPs
- Implement Rust output generation (JSON via serde_json)
- Measure: parse speed, memory usage, binary size, build complexity

**Acceptance:** Rust path is at least 5x faster than optimized Python on 100K+ packet captures. Python integration works via import.

### Sprint 8 — Partial Rust Integration
**Goal:** Ship a hybrid parser where Rust handles hot paths, Python orchestrates.

**Tasks:**
- Define Rust-Python contract: what data crosses the boundary and how
- Implement Rust core: parse PCAP → produce device and conversation structs
- Build Python wrapper: call Rust core, translate results to Python objects
- Keep Python output formatting (CSV/JSON writers) orchestrating Rust parse results
- Ensure regression tests pass with hybrid path
- Add --engine flag: python, rust, auto (choose best)
- Build wheels for target platforms (Linux x86_64, macOS ARM64)
- Write hybrid architecture docs

**Acceptance:** `--engine rust` processes the 100K-packet benchmark at least 5x faster with identical output.

### Sprint 9 — Full Rust Rewrite (MVP)
**Goal:** Complete standalone Rust binary with feature parity to Python parser.

**Tasks:**
- Port all Python features to Rust: device discovery, vendor lookup, IP mapping, port tracking, conversation analysis, conversation status, TCP flags, VLAN, DiffServ
- Implement Rust CSV writer with same schema as Python output
- Implement Rust JSON writer with serde (same schema)
- Add CLI with clap: identical flags to Python version
- Write Rust unit tests for all modules
- Run full regression suite against Rust output
- Package as single binary (no Python dependency)
- Benchmark against Python on all fixture sizes

**Acceptance:** Rust binary produces bit-identical output to Python for all regression fixtures. Standalone binary <20MB.

### Sprint 10 — Advanced Analysis Features
**Goal:** Go beyond basic device/conversation extraction to provide analyst-ready intelligence.

**Tasks:**
- Implement device role inference: based on ports open, traffic patterns, MAC OUI (router, switch, firewall, server, workstation, IoT, printer)
- Add network segment discovery: infer subnets, VLAN boundaries, gateway IPs from traffic patterns
- Implement topology inference: which devices talk to which, at what volume, over what protocols
- Add anomaly detection: unusual port usage, unexpected protocols, asymmetric traffic
- Build conversation timeline: time-series of when devices communicated
- Generate automated summary report: executive summary of capture (N devices, M conversations, top talkers, unusual traffic)
- Add GeoIP enrichment for public IPs (MaxMind database)
- Implement PCAP slicing: extract subset of packets matching criteria

**Acceptance:** Running on a real enterprise PCAP produces a readable summary that a network engineer would find useful.

### Sprint 11 — Testing, CI & Quality Gates
**Goal:** Production-grade test coverage and automated quality enforcement.

**Tasks:**
- Achieve >80% code coverage on Python parser (pytest-cov)
- Achieve >90% code coverage on Rust parser (cargo-tarpaulin)
- Add fuzz testing: generate random/malformed PCAPs, verify parser doesn't crash
- Implement property-based testing: for any valid PCAP, device count ≤ packet count
- Add memory leak detection (valgrind for Rust, memray for Python)
- Build CI pipeline: lint (ruff/clippy), test, benchmark, regression
- Add performance regression gates: CI fails if benchmark regresses >10%
- Write CONTRIBUTING.md with dev setup instructions

**Acceptance:** CI runs on every PR. Benchmark regression gates prevent accidental slowdowns.

### Sprint 12 — Distribution & Ship Readiness
**Goal:** The tool is easy to install, run, and integrate into other workflows.

**Tasks:**
- Package Python parser as pip-installable package (pyproject.toml, setuptools)
- Publish Rust binary as GitHub Release (cross-compiled for linux/amd64, linux/arm64, macos/arm64, windows/amd64)
- Write comprehensive README with quickstart, examples, and reference
- Add Docker image: `docker run -v $(pwd):/data pcap-parser /data/capture.pcap`
- Implement library mode: importable Python module (`from pcap_parser import parse`)
- Add JSON streaming output for integration with piped workflows
- Write man page and shell completion scripts (bash, zsh, fish)
- Create example gallery: screenshots of outputs, visualization examples

**Acceptance:** A user can `pip install pcap-parser` or download a binary and parse a PCAP in one command.

---

## Architecture decision log

| Decision | Rationale |
|----------|-----------|
| Python as reference implementation | Ease of development, broader contributor base, existing PyShark ecosystem |
| Rust for acceleration, not replacement | Incremental adoption path; Python stays for orchestration until Rust is proven |
| PyO3 for Rust-Python bridge | Most mature, best performance, pip-installable wheels |
| JSON Schema for output contract | Machine-verifiable, version-able, broad tool support |
| Golden file regression testing | Simplest way to catch accidental output changes |

## Acceptance criteria
A release is good when:
- it parses representative PCAPs without manual cleanup
- outputs are consistent, schema-valid, and well-structured
- performance is measured and improving (or at least not regressing)
- the Rust path (if active) produces identical results to Python
- the tool is installable in one command

## Validation
Use the Docker dev/test server for:
- regression tests against golden fixtures
- benchmark runs on standardized PCAPs
- output schema validation
- cross-implementation comparison (Python vs Rust)
- CI pipeline verification

## Priorities
1. Stabilize schemas and regression testing (quality foundation)
2. Profile and optimize Python hot paths
3. Build Rust proof-of-concept and decide on full rewrite
4. Add advanced analysis features
5. Package for distribution and community adoption

## Success definition
This project is successful when a user can point it at any PCAP and get accurate, useful device and conversation intelligence quickly enough to support real analysis work — and when the architecture supports continued evolution without fragility.
