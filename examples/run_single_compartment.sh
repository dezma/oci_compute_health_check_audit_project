#!/usr/bin/env bash
set -euo pipefail
COMPARTMENT_OCID="$1"
python3 oci_compute_audit.py --compartment-id "$COMPARTMENT_OCID" --include-agent-plugins
