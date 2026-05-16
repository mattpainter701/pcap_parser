# Regression Fixture System

The regression harness locks parser output to committed golden artifacts so schema and behavior changes are intentional.

## Manifest

Fixtures live in `fixtures/regression_manifest.json`. Each fixture points to a PCAP and one or more golden outputs:

```json
{
  "name": "vlan_240_tagged",
  "pcap": "../pcaps/vlan-240.pcapng",
  "goldens": {
    "device_csv": "../outputs/vlan-240-device_info.csv",
    "conversation_csv": "../outputs/vlan-240-conversation_info.csv",
    "network_json": "../outputs/vlan-240-network_data.json"
  }
}
```

Supported artifact keys are:

- `device_csv`
- `conversation_csv`
- `network_json`

## Running the suite

Fast contract check using committed goldens only:

```bash
python -m pytest tests/test_regression_harness.py
python pcap_parser.py --regression
```

Compare freshly regenerated parser outputs against goldens:

```bash
python pcap_parser.py pcaps/vlan-240.pcapng --output-dir /tmp/pcap-outputs --validate-output
python pcap_parser.py --regression --regression-actual-dir /tmp/pcap-outputs
```

The harness canonicalizes row ordering, list ordering, timestamp precision, TCP flag ordering, and generated JSON timestamps before comparing artifacts. This keeps expected non-determinism from causing false failures while still catching material output changes.

## Adding a fixture

1. Add a small, redistributable PCAP to `pcaps/`.
2. Generate outputs with the parser:
   ```bash
   python pcap_parser.py pcaps/example.pcapng --output-dir outputs --validate-output
   ```
3. Add the PCAP and generated outputs to `fixtures/regression_manifest.json`.
4. Run:
   ```bash
   python -m pytest tests/test_regression_harness.py
   python pcap_parser.py --regression
   ```
5. If the golden diff is intentional, commit the PCAP, outputs, and manifest update together.

## Current coverage

- Mixed IPv4 baseline: device CSV, conversation CSV, network JSON.
- VLAN-tagged baseline: device CSV, conversation CSV, network JSON.

Future fixtures should add IPv6-only, mixed IPv4/IPv6, fragmented packets, encrypted/TLS-heavy traffic, MPLS, and larger captures as redistributable samples become available.
