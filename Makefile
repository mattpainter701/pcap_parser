.PHONY: test smoke package verify clean

test:
	python3 -m pytest --tb=short -q

smoke:
	python3 pcap_parser.py --help >/dev/null
	python3 pcap_parser.py --regression

package:
	python3 -m venv .venv-build
	.venv-build/bin/python -m pip install --upgrade pip build
	.venv-build/bin/python -m build --sdist --wheel

verify:
	python3 -m pytest --tb=short -q
	bash scripts/verify_package.sh

clean:
	rm -rf build dist *.egg-info .venv-build .pytest_cache __pycache__
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
