# Release Checklist

Use this checklist for CI-friendly verification before tagging a pcap-parser release.

## Preflight
- [ ] Confirm `main` is up to date with `origin/main`.
- [ ] Confirm `pyproject.toml` version matches the intended release tag.
- [ ] Review `docs/output-schema.md` for schema/version compatibility notes.
- [ ] Review `fixtures/regression_manifest.json` for committed fixture coverage.

## Verification
Run the deterministic smoke and package checks from a clean checkout:

```bash
python3 -m pytest --tb=short -q
bash scripts/verify_package.sh
```

The package verifier intentionally avoids global `pip install`; it builds in a temporary virtual environment so Debian/Ubuntu PEP 668 environments stay untouched.

## Tagging
- [ ] Create an annotated tag: `git tag -a vX.Y.Z -m "pcap-parser vX.Y.Z"`.
- [ ] Push `main` and the tag after tests pass.
- [ ] Attach generated distribution artifacts from `dist/` if publishing a GitHub release.

## Post-release smoke
- [ ] Install the wheel in a fresh virtual environment.
- [ ] Run `pcap-parser --help`.
- [ ] Run one small fixture parse and compare the JSON/CSV outputs against the schema docs.
