# OCI Compute Health Check Audit

`oci_compute_health_check_audit` is a Python project that audits OCI Compute deployments using the OCI Python SDK.

It is designed to run well in **OCI Cloud Shell**, and it also works from a **local workstation** when standard OCI SDK config-file authentication is available.

## Quick run examples

### 1) Local workstation using OCI config-file authentication

This works on Linux, macOS, or Windows with Python 3, the OCI SDK installed, and a valid `~/.oci/config`. Oracle documents config-file authentication as the standard SDK pattern for local execution.

```bash
python3 -m pip install -r requirements.txt
python3 oci_compute_audit.py --auth config --profile DEFAULT --region eu-frankfurt-1 --compartment-id <compartment_ocid>
```

### 2) OCI compute instance using Instance Principals

```bash
python3 -m pip install -r requirements.txt
python3 oci_compute_audit.py --auth instance_principal --region eu-frankfurt-1 --compartment-id <compartment_ocid>
```

If your SDK environment cannot infer the tenancy OCID from the signer, pass it explicitly:

```bash
python3 oci_compute_audit.py --auth instance_principal --region eu-frankfurt-1 --tenancy-id <tenancy_ocid> --compartment-id <compartment_ocid>
```

### 3) OCI Cloud Shell

Cloud Shell remains the easiest runtime because the OCI CLI and Python SDK environment are already present and authenticated through the Cloud Shell session. Use normal config-style auth there unless you have a specific reason to test another mode.

```bash
unzip oci_compute_health_check_audit_project.zip
cd oci_compute_health_check_audit_project
python3 -m pip install --user -r requirements.txt
python3 oci_compute_audit.py --auth config --compartment-id <compartment_ocid>
```

Authentication mode summary:
- `--auth config`: use `~/.oci/config` or the active Cloud Shell config/profile
- `--auth instance_principal`: use native OCI instance principal authentication on a compute instance
- if `--auth` is omitted, the tool defaults to `config` unless `OCI_CLI_AUTH=instance_principal` is set

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

Run in the current SDK config region:

```bash
python3 oci_compute_audit.py --auth config
```

Run across all subscribed regions:

```bash
python3 oci_compute_audit.py --all-regions
```

Run for a single compartment:

```bash
python3 oci_compute_audit.py --auth config --compartment-id ocid1.compartment.oc1..example
```

Force a specific region:

```bash
python3 oci_compute_audit.py --auth config --region eu-frankfurt-1 --compartment-id ocid1.compartment.oc1..example
```

Include Oracle Cloud Agent plugin checks:

```bash
python3 oci_compute_audit.py --include-agent-plugins
```


Use Instance Principals on an OCI compute instance:

```bash
python3 oci_compute_audit.py --auth instance_principal --region eu-frankfurt-1 --compartment-id ocid1.compartment.oc1..example
```

Use Instance Principals across all subscribed regions:

```bash
python3 oci_compute_audit.py --auth instance_principal --all-regions --compartment-id ocid1.compartment.oc1..example
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

## Policy file structure and explanations

The policy file is optional. If you do not provide one, the tool uses built-in defaults.

The policy has four top-level sections:

### `thresholds`
Numeric thresholds used by the audit engine.

Supported keys in the current project:

- `cpu_scale_up_pct`  
  If average CPU is at or above this value, the instance is considered an `UPSCALE_CANDIDATE`.

- `memory_scale_up_pct`  
  If average memory is at or above this value, the instance is also considered an `UPSCALE_CANDIDATE`.

- `cpu_scale_down_pct`  
  If average CPU is at or below this value, it becomes eligible for `DOWNSCALE_CANDIDATE` review.

- `memory_scale_down_pct`  
  If average memory is at or below this value, it also becomes eligible for `DOWNSCALE_CANDIDATE` review.

- `disk_iops_busy_threshold`  
  A safety brake for downscale recommendations. If disk activity is above this threshold, the script avoids suggesting a downscale even when CPU and memory are low.

- `network_bytes_busy_threshold`  
  Another safety brake for downscale recommendations. If network traffic is above this threshold, the script avoids suggesting a downscale even when CPU and memory are low.

- `world_open_admin_ports`  
  List of admin ports that should not be open to the world. Used during NSG and security-list rule analysis.

- `world_open_sensitive_ports`  
  List of sensitive application or database ports that should not be open to the world.

- `metrics_lookback_hours`  
  Number of hours of Monitoring data used for average CPU, memory, disk, and network calculations.

### `required_tag_keys`
A list of tag keys expected on every instance.

If one or more are missing, the script produces a `TAGS_MISSING` finding.

Example:

```yaml
required_tag_keys:
  - owner
  - environment
  - application
  - cost_center
```

### `severity_overrides`
A global severity map by finding code.

This lets you change the default severity for a finding everywhere in the estate.

Example:

```yaml
severity_overrides:
  PREEMPTIBLE_INSTANCE: low
  UTILIZATION_DOWNSCALE_CANDIDATE: medium
```

In that example:
- every `PREEMPTIBLE_INSTANCE` finding becomes `low`
- every `UTILIZATION_DOWNSCALE_CANDIDATE` finding becomes `medium`

Supported severity values are:
- `critical`
- `high`
- `medium`
- `low`
- `info`

### `resource_overrides`
Per-resource exception rules.

These rules are evaluated after the global severity override.
A rule only matches when all supplied filters match the current instance.

Supported filters in the current project:
- `finding_code`
- `instance_name_regex`
- `compartment_name_regex`
- `shape_regex`
- `region_regex`
- `tag_equals`
- `severity`

Example:

```yaml
resource_overrides:
  - finding_code: PUBLIC_IP
    instance_name_regex: '^bastion-'
    severity: low
```

That means:
- if the finding code is `PUBLIC_IP`
- and the instance name starts with `bastion-`
- set severity to `low`

Another example:

```yaml
resource_overrides:
  - finding_code: PUBLIC_IP
    tag_equals:
      internet_facing_approved: 'true'
    severity: low
```

That means:
- if the finding code is `PUBLIC_IP`
- and the instance has the tag `internet_facing_approved=true`
- set severity to `low`

## Policy evaluation order

The final severity for a finding is decided in this order:

1. built-in finding severity from the code
2. matching `severity_overrides` entry, if present
3. matching `resource_overrides` rule, if present

So `resource_overrides` is the most specific and wins last.

## Example policy file

See the included example:

```text
policies/policy.example.yaml
```

That file now includes inline comments so it can be used as both a template and a reference guide.

## Notes and practical caveats

- Utilization recommendations depend on OCI Monitoring data being available for the instance.
- Memory and compute-agent metrics generally require the Compute Instance Monitoring plugin to be enabled and healthy.
- Some optional services may not be enabled or permitted in every tenancy. The script records best-effort findings and continues.
- Security Zone, OS Management Hub, and Vulnerability Scanning checks are intentionally defensive. If the relevant service APIs are unavailable or restricted, the script degrades gracefully instead of failing the entire run.
- The right-sizing logic is heuristic. Treat it as a shortlist for review, not as an automatic reshape decision engine.
- Instance Principal authentication is not yet wired into the current CLI code path.

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
