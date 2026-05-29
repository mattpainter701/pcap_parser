#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT
python3 -m venv "$TMPDIR/venv"
"$TMPDIR/venv/bin/python" -m pip install --upgrade pip build >/dev/null
"$TMPDIR/venv/bin/python" -m build --sdist --wheel
wheel_file="$(ls -1 dist/*.whl | tail -1)"
"$TMPDIR/venv/bin/python" -m pip install --force-reinstall "$wheel_file" >/dev/null
"$TMPDIR/venv/bin/pcap-parser" --help >/dev/null
"$TMPDIR/venv/bin/python" - <<'PYCODE'
import importlib.metadata as metadata
version = metadata.version('pcap-parser')
assert version, 'package version is empty'
print(f'pcap-parser package verification passed: {version}')
PYCODE
