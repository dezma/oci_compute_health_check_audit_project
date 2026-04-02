# OCI Compute Health Check Audit

`oci_compute_health_check_audit` is a Cloud Shell-friendly Python project that audits OCI Compute deployments using the **OCI Python SDK**.

It is designed to work directly from an unzipped project in **OCI Cloud Shell**, while still supporting editable installation as a package.

## Project naming

- Project/package name: `oci_compute_health_check_audit`
- Main launcher script: `oci_compute_audit.py`
- CLI entry point after install: `oci-compute-health-check-audit`

## What this version checks

### Core inventory
- regions, compartments, ADs, fault domains
- shape, shape config, image, lifecycle state
- primary VNIC, private/public IP, subnet, NSGs, security lists
- boot volume and attached block volumes
- tags and basic landing-zone alignment signals

### Security and network posture
- public IP exposure
- IMDS legacy endpoint status
- NSG and security-list ingress rule review
- world-open admin ports such as SSH and RDP
- world-open sensitive database/service ports
- no-NSG-on-primary-VNIC detection

### Security Zone awareness
- compartment alignment with Security Zones when detectable through OCI APIs
- public exposure conflicts for security-zone-aligned workloads
- boot-volume KMS visibility checks for security-zone-aligned workloads

### Fleet architecture
- instance pool membership
- autoscaling configuration discovery for instance pools
- capacity reservation usage
- preemptible instance usage

### Operations coverage
- OS Management Hub managed-instance coverage
- Vulnerability Scanning host-target coverage by compartment/instance context
- optional Oracle Cloud Agent plugin status checks

### Utilization and right-sizing heuristics
- average CPU utilization
- average memory utilization
- average disk throughput / IOPS metrics when available
- average network throughput metrics when available
- recommendation bucket:
  - `UPSCALE_CANDIDATE`
  - `DOWNSCALE_CANDIDATE`
  - `RIGHT_SIZED_OR_REVIEW`
  - `NO_DATA`

### Reporting
- JSON report
- CSV report
- HTML report
- YAML policy file for severity overrides and thresholds

## Project layout

```text
oci_compute_health_check_audit_project/
├── README.md
├── requirements.txt
├── pyproject.toml
├── Makefile
├── oci_compute_audit.py
├── examples/
│   ├── run_all_regions.sh
│   └── run_single_compartment.sh
├── policies/
│   └── policy.example.yaml
└── src/
    └── oci_compute_health_check_audit/
        ├── __init__.py
        └── cli.py
```

## Cloud Shell quick start

Cloud Shell is the target environment.

```bash
unzip oci_compute_health_check_audit_project.zip
cd oci_compute_health_check_audit_project
python3 -m pip install --user -r requirements.txt
python3 oci_compute_audit.py
```

That writes JSON, CSV, and HTML files in the current directory.

## Package install

```bash
cd oci_compute_health_check_audit_project
python3 -m pip install --user -r requirements.txt
python3 -m pip install --user -e .
oci-compute-health-check-audit
```

## Common usage

Run in the current Cloud Shell region:

```bash
python3 oci_compute_audit.py
```

Run across all subscribed regions:

```bash
python3 oci_compute_audit.py --all-regions
```

Run for a single compartment:

```bash
python3 oci_compute_audit.py --compartment-id ocid1.compartment.oc1..example
```

Include Oracle Cloud Agent plugin checks:

```bash
python3 oci_compute_audit.py --include-agent-plugins
```

Use a policy file:

```bash
python3 oci_compute_audit.py --policy-file policies/policy.example.yaml
```

Disable utilization collection when you want a faster inventory/security-only run:

```bash
python3 oci_compute_audit.py --disable-utilization
```

## Output files

The tool creates timestamped output such as:

```text
oci_compute_health_check_audit_20260402_112500.json
oci_compute_health_check_audit_20260402_112500.csv
oci_compute_health_check_audit_20260402_112500.html
```

## Policy file structure

Example YAML:

```yaml
thresholds:
  cpu_scale_up_pct: 80
  memory_scale_up_pct: 85
  cpu_scale_down_pct: 12
  memory_scale_down_pct: 30

required_tag_keys:
  - owner
  - environment
  - application
  - cost_center

severity_overrides:
  PREEMPTIBLE_INSTANCE: low
  UTILIZATION_DOWNSCALE_CANDIDATE: medium

resource_overrides:
  - finding_code: PUBLIC_IP
    instance_name_regex: '^bastion-'
    severity: low
```

## Notes and practical caveats

- Utilization recommendations depend on OCI Monitoring data being available for the instance.
- Memory and compute-agent metrics generally require the Compute Instance Monitoring plugin to be enabled and healthy.
- Some optional services may not be enabled or permitted in every tenancy. The script records best-effort findings and continues.
- Security Zone, OS Management Hub, and Vulnerability Scanning checks are intentionally defensive. If the relevant service APIs are unavailable or restricted, the script degrades gracefully instead of failing the entire run.
- The right-sizing logic is heuristic. Treat it as a shortlist for review, not as an automatic reshape decision engine.

## Exit codes

- `0` success
- `2` configuration or setup issue
- `130` interrupted by user

## Development

Syntax check:

```bash
make lint
```

Run from repo root:

```bash
make run
```

Install editable package:

```bash
make install
```
