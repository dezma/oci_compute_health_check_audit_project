.PHONY: help install run lint

help:
	@echo "install  - install package in editable mode"
	@echo "run      - run the audit locally from the repo"
	@echo "lint     - basic syntax validation"

install:
	python3 -m pip install --user -r requirements.txt
	python3 -m pip install --user -e .

run:
	python3 oci_compute_audit.py

lint:
	python3 -m py_compile oci_compute_audit.py src/oci_compute_health_check_audit/__init__.py src/oci_compute_health_check_audit/cli.py
