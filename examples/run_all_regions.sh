#!/usr/bin/env bash
set -euo pipefail
python3 oci_compute_audit.py --all-regions --include-agent-plugins --policy-file policies/policy.example.yaml
