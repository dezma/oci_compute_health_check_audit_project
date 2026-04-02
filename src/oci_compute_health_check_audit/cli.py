#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import sys
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # pragma: no cover
    import yaml
except Exception:  # pragma: no cover
    yaml = None

try:  # pragma: no cover
    import oci
    from oci.pagination import list_call_get_all_results
except Exception:  # pragma: no cover
    oci = None
    list_call_get_all_results = None


DEFAULT_TIMEOUT = (10, 60)
DEFAULT_RETRY = getattr(getattr(oci, "retry", None), "DEFAULT_RETRY_STRATEGY", None) if oci else None
ACTIVE_STATES = {"RUNNING", "PROVISIONING", "STARTING", "STOPPING", "STOPPED", "ACTIVE"}
SEVERITY_SCORE = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 1}
DEFAULT_TAG_KEYS = ["owner", "environment", "application", "cost_center"]
DEFAULT_POLICY = {
    "thresholds": {
        "cpu_scale_up_pct": 80.0,
        "memory_scale_up_pct": 85.0,
        "cpu_scale_down_pct": 15.0,
        "memory_scale_down_pct": 35.0,
        "disk_iops_busy_threshold": 3000.0,
        "network_bytes_busy_threshold": 50_000_000.0,
        "world_open_admin_ports": [22, 3389],
        "world_open_sensitive_ports": [1521, 3306, 5432, 6379, 9200, 27017],
        "metrics_lookback_hours": 24,
    },
    "severity_overrides": {},
    "resource_overrides": [],
    "required_tag_keys": DEFAULT_TAG_KEYS,
}


class AuditError(Exception):
    pass


@dataclass
class Finding:
    code: str
    severity: str
    category: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "data": self.data,
        }


@dataclass
class Policy:
    thresholds: Dict[str, Any]
    severity_overrides: Dict[str, str]
    resource_overrides: List[Dict[str, Any]]
    required_tag_keys: List[str]

    @classmethod
    def load(cls, path: Optional[str]) -> "Policy":
        base = json.loads(json.dumps(DEFAULT_POLICY))
        if not path:
            return cls(**base)

        raw: Dict[str, Any] = {}
        p = Path(path)
        if not p.exists():
            raise AuditError(f"Policy file not found: {path}")

        if p.suffix.lower() == ".json":
            raw = json.loads(p.read_text(encoding="utf-8"))
        else:
            if yaml is None:
                raise AuditError(
                    "PyYAML is required when using a YAML policy file. Install dependencies with: python3 -m pip install -r requirements.txt"
                )
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

        merged = json.loads(json.dumps(base))
        merged["thresholds"].update(raw.get("thresholds", {}) or {})
        merged["severity_overrides"].update(raw.get("severity_overrides", {}) or {})
        merged["resource_overrides"] = list(raw.get("resource_overrides", []) or [])
        merged["required_tag_keys"] = list(raw.get("required_tag_keys", base["required_tag_keys"]))
        return cls(**merged)

    def apply(self, finding: Finding, instance_row: Dict[str, Any]) -> Finding:
        severity = self.severity_overrides.get(finding.code, finding.severity)
        for rule in self.resource_overrides:
            if rule.get("finding_code") and rule["finding_code"] != finding.code:
                continue
            if not self._resource_rule_matches(rule, instance_row):
                continue
            severity = rule.get("severity", severity)
        finding.severity = severity.lower()
        return finding

    @staticmethod
    def _resource_rule_matches(rule: Dict[str, Any], row: Dict[str, Any]) -> bool:
        checks = {
            "instance_name_regex": row.get("instance_name", ""),
            "compartment_name_regex": row.get("compartment_name", ""),
            "shape_regex": row.get("shape", ""),
            "region_regex": row.get("region", ""),
        }
        for key, value in checks.items():
            pattern = rule.get(key)
            if pattern and not re.search(pattern, value or ""):
                return False
        tag_equals = rule.get("tag_equals", {}) or {}
        row_tags = row.get("all_tags", {}) or {}
        for k, v in tag_equals.items():
            if str(row_tags.get(k)) != str(v):
                return False
        return True


class ClientFactory:
    def __init__(self, base_config: Dict[str, Any]) -> None:
        self.base_config = dict(base_config)
        self._clients: Dict[Tuple[str, str], Any] = {}

    def _cfg(self, region: str) -> Dict[str, Any]:
        cfg = dict(self.base_config)
        cfg["region"] = region
        return cfg

    def get(self, region: str, service: str):
        if oci is None:
            raise AuditError("OCI Python SDK is required. Run this in OCI Cloud Shell or install the OCI SDK.")
        key = (region, service)
        if key in self._clients:
            return self._clients[key]
        cfg = self._cfg(region)
        kwargs = {"timeout": DEFAULT_TIMEOUT}
        if DEFAULT_RETRY is not None:
            kwargs["retry_strategy"] = DEFAULT_RETRY

        mapping = {
            "identity": oci.identity.IdentityClient,
            "compute": oci.core.ComputeClient,
            "compute_mgmt": oci.core.ComputeManagementClient,
            "network": oci.core.VirtualNetworkClient,
            "block": oci.core.BlockstorageClient,
            "monitoring": oci.monitoring.MonitoringClient,
            "autoscaling": getattr(oci, "autoscaling", None).AutoScalingClient if getattr(oci, "autoscaling", None) else None,
            "cloud_guard": getattr(oci, "cloud_guard", None).CloudGuardClient if getattr(oci, "cloud_guard", None) else None,
            "vss": getattr(oci, "vulnerability_scanning", None).VulnerabilityScanningClient if getattr(oci, "vulnerability_scanning", None) else None,
            "osmh": getattr(oci, "os_management_hub", None).ManagedInstanceClient if getattr(oci, "os_management_hub", None) else None,
            "agent_plugins": getattr(oci, "compute_instance_agent", None).PluginClient if getattr(oci, "compute_instance_agent", None) else None,
        }
        cls = mapping.get(service)
        if cls is None:
            raise AuditError(f"OCI SDK client unavailable for service: {service}")
        client = cls(cfg, **kwargs)
        self._clients[key] = client
        return client


def ocid_last(value: Optional[str]) -> str:
    if not value:
        return ""
    return value.split(".")[-1][:12]


def safe_getattr(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def flatten_tags(defined_tags: Optional[Dict[str, Any]], freeform_tags: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (freeform_tags or {}).items():
        out[str(k)] = str(v)
    for ns, values in (defined_tags or {}).items():
        if isinstance(values, dict):
            for k, v in values.items():
                out[f"{ns}.{k}"] = str(v)
                out.setdefault(str(k), str(v))
    return out


def model_to_dict(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if depth > 4:
        return str(value)
    if isinstance(value, list):
        return [model_to_dict(v, depth + 1) for v in value]
    if isinstance(value, dict):
        return {str(k): model_to_dict(v, depth + 1) for k, v in value.items()}
    attribute_map = getattr(value, "attribute_map", None)
    if isinstance(attribute_map, dict):
        return {k: model_to_dict(getattr(value, k, None), depth + 1) for k in attribute_map.keys()}
    if hasattr(value, "__dict__"):
        return {k: model_to_dict(v, depth + 1) for k, v in value.__dict__.items() if not k.startswith("_")}
    return str(value)


def html_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "<p class='muted'>No rows.</p>"
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


class OciComputeHealthCheckAudit:
    def __init__(self, args: argparse.Namespace) -> None:
        if oci is None:
            raise AuditError(
                "OCI Python SDK is not available in this environment. Run in OCI Cloud Shell or install the SDK first."
            )
        self.args = args
        self.policy = Policy.load(args.policy_file)
        self.base_config = self._load_config(args.profile, args.region)
        self.tenancy_id = self.base_config["tenancy"]
        self.home_region = self.base_config["region"]
        self.clients = ClientFactory(self.base_config)
        self.identity_home = self.clients.get(self.home_region, "identity")
        self.regions = self._resolve_regions()
        self.compartments = self._resolve_compartments()
        self.compartment_name_by_id = {c["id"]: c["name"] for c in self.compartments}

        self.image_cache: Dict[Tuple[str, str], str] = {}
        self.subnet_cache: Dict[Tuple[str, str], Any] = {}
        self.vnic_cache: Dict[Tuple[str, str], Any] = {}
        self.nsg_rules_cache: Dict[Tuple[str, str], List[Any]] = {}
        self.security_list_cache: Dict[Tuple[str, str], Any] = {}
        self.boot_backup_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self.block_backup_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self.security_zone_map: Dict[str, Dict[str, Any]] = {}
        self.region_context: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _load_config(profile: Optional[str], region_override: Optional[str]) -> Dict[str, Any]:
        config_file = os.environ.get("OCI_CLI_CONFIG_FILE")
        effective_profile = profile or os.environ.get("OCI_CLI_PROFILE") or "DEFAULT"
        try:
            cfg = (
                oci.config.from_file(file_location=config_file, profile_name=effective_profile)
                if config_file
                else oci.config.from_file(profile_name=effective_profile)
            )
        except Exception as exc:
            raise AuditError(f"Unable to load OCI config using profile '{effective_profile}'.") from exc
        if region_override:
            cfg["region"] = region_override
        return cfg

    def _resolve_regions(self) -> List[str]:
        if self.args.all_regions:
            subs = list_call_get_all_results(self.identity_home.list_region_subscriptions, self.tenancy_id).data
            return sorted({r.region_name for r in subs if getattr(r, "status", "READY") == "READY"})
        if self.args.region_list:
            return [x.strip() for x in self.args.region_list.split(",") if x.strip()]
        return [self.base_config["region"]]

    def _resolve_compartments(self) -> List[Dict[str, str]]:
        if self.args.compartment_id:
            cid = self.args.compartment_id
            name = cid
            try:
                if cid == self.tenancy_id:
                    name = self.identity_home.get_tenancy(cid).data.name
                else:
                    name = self.identity_home.get_compartment(cid).data.name
            except Exception:
                pass
            return [{"id": cid, "name": name}]

        roots = [{"id": self.tenancy_id, "name": self.identity_home.get_tenancy(self.tenancy_id).data.name}]
        response = list_call_get_all_results(
            self.identity_home.list_compartments,
            self.tenancy_id,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
        ).data
        for c in response:
            if getattr(c, "lifecycle_state", None) == "ACTIVE":
                roots.append({"id": c.id, "name": c.name})
        return roots

    def run(self) -> Dict[str, Any]:
        self._prefetch_security_zones()
        for region in self.regions:
            self.region_context[region] = self._build_region_context(region)

        rows: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        all_findings: List[Dict[str, Any]] = []

        for region in self.regions:
            compute = self.clients.get(region, "compute")
            for compartment in self.compartments:
                try:
                    instances = list_call_get_all_results(compute.list_instances, compartment["id"]).data
                except Exception as exc:
                    errors.append(
                        {
                            "region": region,
                            "compartment_id": compartment["id"],
                            "compartment_name": compartment["name"],
                            "error": f"list_instances failed: {exc}",
                        }
                    )
                    continue

                for instance_summary in instances:
                    state = safe_getattr(instance_summary, "lifecycle_state", default="UNKNOWN")
                    if self.args.active_only and state not in ACTIVE_STATES:
                        continue
                    if not self.args.include_terminated and state == "TERMINATED":
                        continue
                    try:
                        row, findings = self._audit_instance(region, compartment, instance_summary.id)
                        rows.append(row)
                        all_findings.extend([dict(item, instance_id=row["instance_id"], instance_name=row["instance_name"]) for item in findings])
                    except Exception as exc:
                        errors.append(
                            {
                                "region": region,
                                "compartment_id": compartment["id"],
                                "compartment_name": compartment["name"],
                                "instance_id": getattr(instance_summary, "id", "unknown"),
                                "instance_name": getattr(instance_summary, "display_name", "unknown"),
                                "error": f"instance audit failed: {exc}",
                            }
                        )
                        if self.args.verbose:
                            traceback.print_exc(file=sys.stderr)

        report = {
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "project": "oci_compute_health_check_audit",
            "script": "oci_compute_audit.py",
            "config": {
                "profile": self.args.profile or os.environ.get("OCI_CLI_PROFILE") or "DEFAULT",
                "regions": self.regions,
                "active_only": self.args.active_only,
                "include_agent_plugins": self.args.include_agent_plugins,
                "include_utilization": not self.args.disable_utilization,
                "metrics_lookback_hours": self.args.metrics_lookback_hours,
                "policy_file": self.args.policy_file,
            },
            "summary": self._build_summary(rows, errors, all_findings),
            "instances": rows,
            "findings": all_findings,
            "errors": errors,
        }
        return report

    def _build_region_context(self, region: str) -> Dict[str, Any]:
        context = {
            "instance_pool_by_instance_id": {},
            "instance_pool_by_id": {},
            "autoscaling_by_pool_id": defaultdict(list),
            "capacity_reservations": {},
            "osmh_by_instance_id": {},
            "vss_targets_by_compartment": defaultdict(list),
        }
        self._prefetch_instance_pools(region, context)
        self._prefetch_autoscaling(region, context)
        self._prefetch_capacity_reservations(region, context)
        self._prefetch_osmh(region, context)
        self._prefetch_vss(region, context)
        return context

    def _prefetch_security_zones(self) -> None:
        for region in self.regions:
            try:
                client = self.clients.get(region, "cloud_guard")
            except Exception:
                continue
            list_fn = getattr(client, "list_security_zones", None)
            if not callable(list_fn):
                continue
            try:
                items = list_call_get_all_results(list_fn, self.tenancy_id, compartment_id_in_subtree=True).data
            except Exception:
                try:
                    items = list_call_get_all_results(list_fn, self.tenancy_id).data
                except Exception:
                    continue
            for item in items:
                comp_id = safe_getattr(item, "compartment_id")
                if comp_id:
                    self.security_zone_map[comp_id] = {
                        "region": region,
                        "id": safe_getattr(item, "id"),
                        "name": safe_getattr(item, "display_name", default=safe_getattr(item, "id", default="security-zone")),
                        "lifecycle_state": safe_getattr(item, "lifecycle_state"),
                    }

    def _prefetch_instance_pools(self, region: str, context: Dict[str, Any]) -> None:
        try:
            mgmt = self.clients.get(region, "compute_mgmt")
        except Exception:
            return
        for comp in self.compartments:
            try:
                pools = list_call_get_all_results(mgmt.list_instance_pools, comp["id"]).data
            except Exception:
                continue
            for pool in pools:
                pool_info = {
                    "id": pool.id,
                    "name": safe_getattr(pool, "display_name"),
                    "size": safe_getattr(pool, "size"),
                    "state": safe_getattr(pool, "lifecycle_state"),
                    "instance_configuration_id": safe_getattr(pool, "instance_configuration_id"),
                    "placement_configurations": model_to_dict(safe_getattr(pool, "placement_configurations", default=[])),
                    "defined_tags": model_to_dict(safe_getattr(pool, "defined_tags", default={})),
                    "freeform_tags": model_to_dict(safe_getattr(pool, "freeform_tags", default={})),
                }
                context["instance_pool_by_id"][pool.id] = pool_info
                try:
                    members = list_call_get_all_results(mgmt.list_instance_pool_instances, comp["id"], pool.id).data
                except Exception:
                    continue
                for member in members:
                    iid = safe_getattr(member, "id", "instance_id")
                    if iid:
                        context["instance_pool_by_instance_id"][iid] = pool_info

    def _prefetch_autoscaling(self, region: str, context: Dict[str, Any]) -> None:
        try:
            client = self.clients.get(region, "autoscaling")
        except Exception:
            return
        list_fn = getattr(client, "list_auto_scaling_configurations", None)
        if not callable(list_fn):
            return
        for comp in self.compartments:
            try:
                configs = list_call_get_all_results(list_fn, comp["id"]).data
            except Exception:
                continue
            for cfg in configs:
                as_dict = model_to_dict(cfg)
                resources = as_dict.get("auto_scaling_resources") or []
                for resource in resources:
                    pool_id = resource.get("id")
                    if pool_id:
                        context["autoscaling_by_pool_id"][pool_id].append(as_dict)

    def _prefetch_capacity_reservations(self, region: str, context: Dict[str, Any]) -> None:
        try:
            client = self.clients.get(region, "compute")
        except Exception:
            return
        list_fn = getattr(client, "list_compute_capacity_reservations", None)
        if not callable(list_fn):
            return
        for comp in self.compartments:
            try:
                reservations = list_call_get_all_results(list_fn, comp["id"]).data
            except Exception:
                continue
            for res in reservations:
                context["capacity_reservations"][res.id] = {
                    "id": res.id,
                    "name": safe_getattr(res, "display_name"),
                    "state": safe_getattr(res, "lifecycle_state"),
                    "reserved_instance_count": safe_getattr(res, "reserved_instance_count"),
                    "used_instance_count": safe_getattr(res, "used_instance_count"),
                    "availability_domain": safe_getattr(res, "availability_domain"),
                }

    def _prefetch_osmh(self, region: str, context: Dict[str, Any]) -> None:
        if self.args.disable_osmh:
            return
        try:
            client = self.clients.get(region, "osmh")
        except Exception:
            return
        list_fn = getattr(client, "list_managed_instances", None)
        if not callable(list_fn):
            return
        for comp in self.compartments:
            try:
                items = list_call_get_all_results(list_fn, comp["id"]).data
            except Exception:
                continue
            for item in items:
                as_dict = model_to_dict(item)
                keys = [
                    as_dict.get("id"),
                    as_dict.get("managed_instance_id"),
                    as_dict.get("instance_id"),
                    as_dict.get("managed_resource_id"),
                ]
                for key in keys:
                    if key and str(key).startswith("ocid1.instance"):
                        context["osmh_by_instance_id"][key] = as_dict

    def _prefetch_vss(self, region: str, context: Dict[str, Any]) -> None:
        if self.args.disable_vss:
            return
        try:
            client = self.clients.get(region, "vss")
        except Exception:
            return
        list_fn = getattr(client, "list_host_scan_targets", None)
        if not callable(list_fn):
            return
        for comp in self.compartments:
            try:
                items = list_call_get_all_results(list_fn, comp["id"]).data
            except Exception:
                continue
            context["vss_targets_by_compartment"][comp["id"]].extend(model_to_dict(x) for x in items)

    def _audit_instance(self, region: str, compartment: Dict[str, str], instance_id: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        compute = self.clients.get(region, "compute")
        network = self.clients.get(region, "network")
        block = self.clients.get(region, "block")
        instance = compute.get_instance(instance_id).data
        state = safe_getattr(instance, "lifecycle_state", default="UNKNOWN")

        row: Dict[str, Any] = {
            "region": region,
            "compartment_id": compartment["id"],
            "compartment_name": compartment["name"],
            "instance_id": instance.id,
            "instance_name": safe_getattr(instance, "display_name", default=instance.id),
            "state": state,
            "availability_domain": safe_getattr(instance, "availability_domain"),
            "fault_domain": safe_getattr(instance, "fault_domain"),
            "shape": safe_getattr(instance, "shape"),
            "shape_ocpus": safe_getattr(safe_getattr(instance, "shape_config", default=None), "ocpus"),
            "shape_memory_gbs": safe_getattr(safe_getattr(instance, "shape_config", default=None), "memory_in_gbs"),
            "image_id": safe_getattr(instance, "image_id"),
            "image_name": self._get_image_name(region, safe_getattr(instance, "image_id")),
            "capacity_type": self._resolve_capacity_type(instance),
            "is_preemptible": self._is_preemptible(instance),
            "capacity_reservation_id": safe_getattr(instance, "capacity_reservation_id"),
            "dedicated_vm_host_id": safe_getattr(instance, "dedicated_vm_host_id"),
        }

        row["defined_tags"] = model_to_dict(safe_getattr(instance, "defined_tags", default={}))
        row["freeform_tags"] = model_to_dict(safe_getattr(instance, "freeform_tags", default={}))
        row["all_tags"] = flatten_tags(row["defined_tags"], row["freeform_tags"])

        primary_vnic, attached_vnics = self._get_primary_vnic(region, compartment["id"], instance.id)
        subnet = self._get_subnet(region, safe_getattr(primary_vnic, "subnet_id")) if primary_vnic else None
        row.update(
            {
                "vnic_count": len(attached_vnics),
                "primary_private_ip": safe_getattr(primary_vnic, "private_ip"),
                "primary_public_ip": safe_getattr(primary_vnic, "public_ip"),
                "subnet_id": safe_getattr(primary_vnic, "subnet_id"),
                "subnet_name": safe_getattr(subnet, "display_name"),
                "vcn_id": safe_getattr(subnet, "vcn_id"),
                "is_subnet_prohibit_public_ip_on_vnic": safe_getattr(subnet, "prohibit_public_ip_on_vnic"),
                "nsg_ids": safe_getattr(primary_vnic, "nsg_ids", default=[]),
                "security_list_ids": safe_getattr(subnet, "security_list_ids", default=[]),
            }
        )

        instance_options = safe_getattr(instance, "instance_options", default=None)
        row["imdsv1_disabled"] = bool(safe_getattr(instance_options, "are_legacy_imds_endpoints_disabled", default=False))

        boot_info = self._get_boot_volume_info(region, compartment["id"], instance)
        row.update(boot_info)
        block_info = self._get_block_volume_info(region, compartment["id"], instance.id)
        row.update(block_info)

        if self.args.include_agent_plugins:
            row.update(self._get_agent_plugin_info(region, compartment["id"], instance.id))

        zone = self._resolve_security_zone(compartment["id"])
        row["security_zone_name"] = zone.get("name") if zone else None
        row["security_zone_id"] = zone.get("id") if zone else None

        ctx = self.region_context[region]
        pool = ctx["instance_pool_by_instance_id"].get(instance.id)
        row["instance_pool_id"] = pool.get("id") if pool else None
        row["instance_pool_name"] = pool.get("name") if pool else None
        row["instance_pool_size"] = pool.get("size") if pool else None
        row["autoscaling_enabled"] = bool(pool and ctx["autoscaling_by_pool_id"].get(pool["id"]))
        row["autoscaling_configs"] = ctx["autoscaling_by_pool_id"].get(pool["id"], []) if pool else []

        cap_res = ctx["capacity_reservations"].get(row["capacity_reservation_id"]) if row["capacity_reservation_id"] else None
        row["capacity_reservation_name"] = cap_res.get("name") if cap_res else None
        row["capacity_reservation_reserved_count"] = cap_res.get("reserved_instance_count") if cap_res else None
        row["capacity_reservation_used_count"] = cap_res.get("used_instance_count") if cap_res else None

        osmh_entry = ctx["osmh_by_instance_id"].get(instance.id)
        row["osmh_managed"] = bool(osmh_entry)
        row["osmh_status"] = None if not osmh_entry else (osmh_entry.get("status") or osmh_entry.get("lifecycle_state"))

        vss_coverage = self._resolve_vss_coverage(ctx, compartment["id"], instance.id)
        row.update(vss_coverage)

        if not self.args.disable_utilization:
            row.update(self._get_utilization(region, compartment["id"], instance.id))
        else:
            row.update(self._empty_utilization())

        findings = self._evaluate_findings(row, subnet=subnet, primary_vnic=primary_vnic)
        row["findings"] = [f["code"] for f in findings]
        row["findings_detail"] = findings
        row["highest_severity"] = self._max_severity(findings)
        row["risk_score"] = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
        return row, findings

    def _resolve_capacity_type(self, instance: Any) -> str:
        if self._is_preemptible(instance):
            return "PREEMPTIBLE"
        if safe_getattr(instance, "capacity_reservation_id"):
            return "CAPACITY_RESERVATION"
        if safe_getattr(instance, "dedicated_vm_host_id"):
            return "DEDICATED_VM_HOST"
        return "ON_DEMAND"

    @staticmethod
    def _is_preemptible(instance: Any) -> bool:
        preemptible = safe_getattr(instance, "preemptible_instance_config")
        return preemptible is not None

    def _resolve_security_zone(self, compartment_id: str) -> Optional[Dict[str, Any]]:
        cid = compartment_id
        while cid:
            if cid in self.security_zone_map:
                return self.security_zone_map[cid]
            parent = None
            try:
                parent = self.identity_home.get_compartment(cid).data.compartment_id if cid != self.tenancy_id else None
            except Exception:
                parent = None
            cid = parent
        return None

    def _get_primary_vnic(self, region: str, compartment_id: str, instance_id: str) -> Tuple[Any, List[Any]]:
        compute = self.clients.get(region, "compute")
        network = self.clients.get(region, "network")
        attachments = list_call_get_all_results(compute.list_vnic_attachments, compartment_id, instance_id=instance_id).data
        vnics: List[Any] = []
        primary = None
        for att in attachments:
            vnic_id = safe_getattr(att, "vnic_id")
            if not vnic_id:
                continue
            vnic = self._get_vnic(region, vnic_id, network)
            vnics.append(vnic)
            if safe_getattr(att, "is_primary_vnic", default=False):
                primary = vnic
        if primary is None and vnics:
            primary = vnics[0]
        return primary, vnics

    def _get_vnic(self, region: str, vnic_id: str, network_client: Any) -> Any:
        key = (region, vnic_id)
        if key not in self.vnic_cache:
            self.vnic_cache[key] = network_client.get_vnic(vnic_id).data
        return self.vnic_cache[key]

    def _get_subnet(self, region: str, subnet_id: Optional[str]) -> Any:
        if not subnet_id:
            return None
        key = (region, subnet_id)
        if key not in self.subnet_cache:
            network = self.clients.get(region, "network")
            self.subnet_cache[key] = network.get_subnet(subnet_id).data
        return self.subnet_cache[key]

    def _get_image_name(self, region: str, image_id: Optional[str]) -> Optional[str]:
        if not image_id:
            return None
        key = (region, image_id)
        if key not in self.image_cache:
            compute = self.clients.get(region, "compute")
            try:
                self.image_cache[key] = compute.get_image(image_id).data.display_name
            except Exception:
                self.image_cache[key] = image_id
        return self.image_cache[key]

    def _get_boot_volume_info(self, region: str, compartment_id: str, instance: Any) -> Dict[str, Any]:
        block = self.clients.get(region, "block")
        compute = self.clients.get(region, "compute")
        info = {
            "boot_volume_id": None,
            "boot_volume_backup_policy": None,
            "boot_volume_kms_key_id": None,
            "boot_volume_size_gbs": None,
        }
        try:
            attachments = list_call_get_all_results(compute.list_boot_volume_attachments, compartment_id, availability_domain=instance.availability_domain, instance_id=instance.id).data
        except Exception:
            return info
        if not attachments:
            return info
        boot_volume_id = safe_getattr(attachments[0], "boot_volume_id")
        if not boot_volume_id:
            return info
        info["boot_volume_id"] = boot_volume_id
        try:
            bv = block.get_boot_volume(boot_volume_id).data
            info["boot_volume_kms_key_id"] = safe_getattr(bv, "kms_key_id")
            info["boot_volume_size_gbs"] = safe_getattr(bv, "size_in_gbs")
        except Exception:
            pass
        info["boot_volume_backup_policy"] = self._get_backup_policy_assignment_name(block, region, boot_volume_id, resource_type="boot")
        return info

    def _get_block_volume_info(self, region: str, compartment_id: str, instance_id: str) -> Dict[str, Any]:
        block = self.clients.get(region, "block")
        compute = self.clients.get(region, "compute")
        out = {
            "block_volume_ids": [],
            "block_volume_count": 0,
            "block_volume_backup_policies": [],
            "block_volume_kms_key_ids": [],
        }
        try:
            attachments = list_call_get_all_results(compute.list_volume_attachments, compartment_id, instance_id=instance_id).data
        except Exception:
            return out
        for att in attachments:
            vid = safe_getattr(att, "volume_id")
            if not vid:
                continue
            out["block_volume_ids"].append(vid)
            try:
                vol = block.get_volume(vid).data
                kms = safe_getattr(vol, "kms_key_id")
                if kms:
                    out["block_volume_kms_key_ids"].append(kms)
            except Exception:
                pass
            policy = self._get_backup_policy_assignment_name(block, region, vid, resource_type="block")
            if policy:
                out["block_volume_backup_policies"].append(policy)
        out["block_volume_count"] = len(out["block_volume_ids"])
        return out

    def _get_backup_policy_assignment_name(self, block_client: Any, region: str, volume_id: str, resource_type: str) -> Optional[str]:
        cache = self.boot_backup_cache if resource_type == "boot" else self.block_backup_cache
        key = (region, volume_id)
        if key in cache:
            return cache[key]
        try:
            assignments = list_call_get_all_results(block_client.list_volume_backup_policy_assignments, asset_id=volume_id).data
            cache[key] = safe_getattr(assignments[0], "policy_name") if assignments else None
        except Exception:
            cache[key] = None
        return cache[key]

    def _get_agent_plugin_info(self, region: str, compartment_id: str, instance_id: str) -> Dict[str, Any]:
        info = {
            "agent_plugins_total": None,
            "agent_plugins_running": None,
            "agent_plugins_stopped": None,
            "agent_compute_monitoring_running": None,
        }
        try:
            client = self.clients.get(region, "agent_plugins")
        except Exception:
            return info
        list_fn = getattr(client, "list_instance_agent_plugins", None)
        if not callable(list_fn):
            return info
        try:
            plugins = list_call_get_all_results(list_fn, compartment_id=compartment_id, instanceagent_id=instance_id).data
        except TypeError:
            try:
                plugins = list_call_get_all_results(list_fn, compartment_id=compartment_id, instance_id=instance_id).data
            except Exception:
                return info
        except Exception:
            return info
        total = len(plugins)
        running = 0
        stopped = 0
        monitoring_running = None
        for p in plugins:
            desired = str(safe_getattr(p, "desired_state", default="")).upper()
            actual = str(safe_getattr(p, "state", default="")).upper()
            name = str(safe_getattr(p, "name", default=""))
            if actual in {"RUNNING", "ACTIVE", "ENABLED"}:
                running += 1
            else:
                stopped += 1
            if "MONITOR" in name.upper():
                monitoring_running = actual in {"RUNNING", "ACTIVE", "ENABLED"} and desired not in {"DISABLED"}
        info.update(
            {
                "agent_plugins_total": total,
                "agent_plugins_running": running,
                "agent_plugins_stopped": stopped,
                "agent_compute_monitoring_running": monitoring_running,
            }
        )
        return info

    def _resolve_vss_coverage(self, ctx: Dict[str, Any], compartment_id: str, instance_id: str) -> Dict[str, Any]:
        targets = ctx["vss_targets_by_compartment"].get(compartment_id, [])
        targeted = False
        matched_names: List[str] = []
        for target in targets:
            text = json.dumps(target, sort_keys=True)
            if compartment_id in text or instance_id in text:
                targeted = True
                matched_names.append(str(target.get("display_name") or target.get("id") or "host-scan-target"))
        return {
            "vss_targeted": targeted or bool(targets),
            "vss_target_count_in_compartment": len(targets),
            "vss_target_names": sorted(set(matched_names)) if matched_names else [str(t.get("display_name") or t.get("id")) for t in targets[:5]],
        }

    def _empty_utilization(self) -> Dict[str, Any]:
        return {
            "cpu_avg_pct": None,
            "memory_avg_pct": None,
            "disk_read_bytes_avg": None,
            "disk_write_bytes_avg": None,
            "disk_iops_read_avg": None,
            "disk_iops_write_avg": None,
            "network_in_bytes_avg": None,
            "network_out_bytes_avg": None,
            "utilization_recommendation": "NO_DATA",
            "utilization_basis": "utilization collection disabled",
        }

    def _get_utilization(self, region: str, compartment_id: str, instance_id: str) -> Dict[str, Any]:
        out = self._empty_utilization()
        monitoring = self.clients.get(region, "monitoring")
        details_cls = oci.monitoring.models.SummarizeMetricsDataDetails
        end_time = dt.datetime.now(dt.timezone.utc)
        lookback_hours = self.args.metrics_lookback_hours or self.policy.thresholds["metrics_lookback_hours"]
        start_time = end_time - dt.timedelta(hours=lookback_hours)
        metric_queries = {
            "cpu_avg_pct": 'CpuUtilization[1h]{resourceId = "%s"}.mean()' % instance_id,
            "memory_avg_pct": 'MemoryUtilization[1h]{resourceId = "%s"}.mean()' % instance_id,
            "disk_read_bytes_avg": 'DiskBytesRead[1h]{resourceId = "%s"}.mean()' % instance_id,
            "disk_write_bytes_avg": 'DiskBytesWritten[1h]{resourceId = "%s"}.mean()' % instance_id,
            "disk_iops_read_avg": 'DiskIopsRead[1h]{resourceId = "%s"}.mean()' % instance_id,
            "disk_iops_write_avg": 'DiskIopsWritten[1h]{resourceId = "%s"}.mean()' % instance_id,
            "network_in_bytes_avg": 'NetworksBytesIn[1h]{resourceId = "%s"}.mean()' % instance_id,
            "network_out_bytes_avg": 'NetworksBytesOut[1h]{resourceId = "%s"}.mean()' % instance_id,
        }
        for key, query in metric_queries.items():
            try:
                resp = monitoring.summarize_metrics_data(
                    compartment_id=compartment_id,
                    summarize_metrics_data_details=details_cls(
                        namespace="oci_computeagent",
                        query=query,
                        start_time=start_time,
                        end_time=end_time,
                    ),
                ).data
                out[key] = self._metric_value(resp)
            except Exception:
                out[key] = None
        out.update(self._recommend_shape_action(out))
        return out

    @staticmethod
    def _metric_value(metric_data: Any) -> Optional[float]:
        if not metric_data:
            return None
        series = metric_data[0]
        aggregated = safe_getattr(series, "aggregated_datapoints", default=[])
        values = []
        for dp in aggregated:
            for attr in ("value", "avg", "mean", "sum"):
                val = getattr(dp, attr, None)
                if val is not None:
                    try:
                        values.append(float(val))
                    except Exception:
                        pass
                    break
        if not values:
            return None
        return round(sum(values) / len(values), 2)

    def _recommend_shape_action(self, utilization: Dict[str, Any]) -> Dict[str, str]:
        cpu = utilization.get("cpu_avg_pct")
        mem = utilization.get("memory_avg_pct")
        net = max(
            utilization.get("network_in_bytes_avg") or 0,
            utilization.get("network_out_bytes_avg") or 0,
        )
        disk_iops = max(
            utilization.get("disk_iops_read_avg") or 0,
            utilization.get("disk_iops_write_avg") or 0,
        )
        t = self.policy.thresholds
        if cpu is None and mem is None:
            return {
                "utilization_recommendation": "NO_DATA",
                "utilization_basis": "monitoring data unavailable or plugin not emitting metrics",
            }
        if (cpu or 0) >= float(t["cpu_scale_up_pct"]) or (mem or 0) >= float(t["memory_scale_up_pct"]):
            return {
                "utilization_recommendation": "UPSCALE_CANDIDATE",
                "utilization_basis": f"cpu={cpu}%, memory={mem}% exceeds upscale threshold",
            }
        if (
            (cpu or 0) <= float(t["cpu_scale_down_pct"])
            and (mem or 0) <= float(t["memory_scale_down_pct"])
            and net <= float(t["network_bytes_busy_threshold"])
            and disk_iops <= float(t["disk_iops_busy_threshold"])
        ):
            return {
                "utilization_recommendation": "DOWNSCALE_CANDIDATE",
                "utilization_basis": f"cpu={cpu}%, memory={mem}%, network={net}, disk_iops={disk_iops} below activity thresholds",
            }
        return {
            "utilization_recommendation": "RIGHT_SIZED_OR_REVIEW",
            "utilization_basis": f"cpu={cpu}%, memory={mem}%, network={net}, disk_iops={disk_iops}",
        }

    def _get_nsg_rules(self, region: str, nsg_id: str) -> List[Any]:
        key = (region, nsg_id)
        if key in self.nsg_rules_cache:
            return self.nsg_rules_cache[key]
        network = self.clients.get(region, "network")
        rules = []
        try:
            rules = list_call_get_all_results(network.list_network_security_group_security_rules, nsg_id).data
        except Exception:
            pass
        self.nsg_rules_cache[key] = rules
        return rules

    def _get_security_list(self, region: str, security_list_id: str) -> Any:
        key = (region, security_list_id)
        if key not in self.security_list_cache:
            network = self.clients.get(region, "network")
            try:
                self.security_list_cache[key] = network.get_security_list(security_list_id).data
            except Exception:
                self.security_list_cache[key] = None
        return self.security_list_cache[key]

    def _evaluate_findings(self, row: Dict[str, Any], subnet: Any, primary_vnic: Any) -> List[Dict[str, Any]]:
        findings: List[Finding] = []
        required_tags = self.policy.required_tag_keys
        missing_tags = [k for k in required_tags if k not in row.get("all_tags", {})]

        if row.get("primary_public_ip"):
            findings.append(Finding("PUBLIC_IP", "high", "network", "Primary VNIC has a public IP address."))
        if row.get("imdsv1_disabled") is False:
            findings.append(Finding("IMDSV1_ENABLED", "medium", "security", "Legacy IMDS endpoints are still enabled."))
        if missing_tags:
            findings.append(Finding("TAGS_MISSING", "medium", "governance", f"Missing recommended tags: {', '.join(missing_tags)}.", {"missing_tags": missing_tags}))
        if not row.get("boot_volume_backup_policy"):
            findings.append(Finding("BOOT_BACKUP_POLICY_MISSING", "high", "resilience", "Boot volume has no backup policy assignment."))
        if row.get("block_volume_count", 0) > 0 and len(row.get("block_volume_backup_policies", [])) < row.get("block_volume_count", 0):
            findings.append(Finding("BLOCK_BACKUP_POLICY_MISSING", "high", "resilience", "One or more attached block volumes have no backup policy assignment."))
        if row.get("vnic_count", 0) > 1:
            findings.append(Finding("MULTI_VNIC_INSTANCE", "low", "operations", "Instance has multiple VNICs; review before reshaping or replatforming."))
        if row.get("block_volume_count", 0) >= 3:
            findings.append(Finding("MULTI_BLOCK_VOLUME_INSTANCE", "low", "operations", "Instance has three or more attached block volumes; review carefully before reshape actions."))
        if not row.get("osmh_managed") and not self.args.disable_osmh:
            findings.append(Finding("OSMH_NOT_MANAGED", "medium", "operations", "Instance is not visible in OS Management Hub inventory."))
        if not row.get("vss_targeted") and not self.args.disable_vss:
            findings.append(Finding("VSS_COVERAGE_MISSING", "medium", "security", "No Vulnerability Scanning host target detected for this instance or its compartment."))
        if row.get("security_zone_name"):
            findings.append(Finding("SECURITY_ZONE_MEMBER", "info", "security", f"Compartment is associated with security zone '{row['security_zone_name']}'."))
            if row.get("primary_public_ip"):
                findings.append(Finding("SECURITY_ZONE_PUBLIC_EXPOSURE", "critical", "security", "Instance appears to have public exposure while inside a security zone scope."))
            if not row.get("boot_volume_kms_key_id"):
                findings.append(Finding("SECURITY_ZONE_KMS_MISSING", "high", "security", "Boot volume does not show a customer-managed KMS key in a security-zone-aligned compartment."))
        if row.get("instance_pool_id"):
            findings.append(Finding("INSTANCE_POOL_MEMBER", "info", "architecture", f"Instance belongs to pool '{row.get('instance_pool_name') or row.get('instance_pool_id')}'."))
            if not row.get("autoscaling_enabled"):
                findings.append(Finding("INSTANCE_POOL_NO_AUTOSCALING", "low", "architecture", "Instance pool has no autoscaling configuration attached."))
        if row.get("capacity_reservation_id"):
            findings.append(Finding("CAPACITY_RESERVATION_IN_USE", "info", "capacity", "Instance is consuming reserved capacity."))
        if row.get("is_preemptible"):
            findings.append(Finding("PREEMPTIBLE_INSTANCE", "info", "capacity", "Instance uses preemptible capacity; validate workload interruption tolerance."))
        if row.get("utilization_recommendation") == "UPSCALE_CANDIDATE":
            findings.append(Finding("UTILIZATION_UPSCALE_CANDIDATE", "medium", "performance", row.get("utilization_basis", "High sustained utilization.")))
        elif row.get("utilization_recommendation") == "DOWNSCALE_CANDIDATE":
            findings.append(Finding("UTILIZATION_DOWNSCALE_CANDIDATE", "low", "cost", row.get("utilization_basis", "Low sustained utilization.")))
        elif row.get("utilization_recommendation") == "NO_DATA":
            findings.append(Finding("UTILIZATION_NO_DATA", "low", "observability", row.get("utilization_basis", "No monitoring data available.")))
        if self.args.include_agent_plugins and row.get("agent_plugins_stopped"):
            findings.append(Finding("AGENT_PLUGINS_STOPPED", "medium", "operations", "One or more Oracle Cloud Agent plugins are not running."))
        if self.args.include_agent_plugins and row.get("agent_compute_monitoring_running") is False:
            findings.append(Finding("COMPUTE_MONITORING_PLUGIN_NOT_RUNNING", "medium", "observability", "Compute Instance Monitoring plugin is not running."))
        if not row.get("nsg_ids"):
            findings.append(Finding("PRIMARY_VNIC_NO_NSG", "low", "network", "Primary VNIC has no NSGs attached; only subnet security lists may be in effect."))

        for rule_finding in self._analyze_network_rules(row):
            findings.append(rule_finding)

        return [self.policy.apply(f, row).to_dict() for f in findings]

    def _analyze_network_rules(self, row: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        admin_ports = set(int(x) for x in self.policy.thresholds.get("world_open_admin_ports", []))
        sensitive_ports = set(int(x) for x in self.policy.thresholds.get("world_open_sensitive_ports", []))
        region = row["region"]

        def analyze_rule(rule: Any, source_label: str) -> None:
            d = model_to_dict(rule)
            if str(d.get("direction", "INGRESS")).upper() not in {"INGRESS", "INBOUND"} and "source" not in d:
                return
            protocol = str(d.get("protocol", d.get("ip_protocol", "")))
            source = str(d.get("source") or d.get("source_cidr_block") or d.get("source_type") or d.get("source_address") or "")
            is_world = source in {"0.0.0.0/0", "::/0"}
            tcp = d.get("tcp_options") or {}
            udp = d.get("udp_options") or {}
            port_min = None
            port_max = None
            if isinstance(tcp, dict):
                dest = tcp.get("destination_port_range") or {}
                port_min = dest.get("min")
                port_max = dest.get("max")
            elif isinstance(udp, dict):
                dest = udp.get("destination_port_range") or {}
                port_min = dest.get("min")
                port_max = dest.get("max")
            if protocol in {"all", "ALL", "-1"} and is_world:
                findings.append(Finding("WORLD_OPEN_ALL_PROTOCOLS", "critical", "network", f"{source_label} allows all protocols from the public internet."))
                return
            if not is_world:
                return
            if port_min is None and protocol in {"6", "17", "tcp", "udp", "TCP", "UDP"}:
                findings.append(Finding("WORLD_OPEN_UNBOUNDED_PORTS", "high", "network", f"{source_label} allows public ingress without a bounded destination port range."))
                return
            if port_min is not None:
                ports = set(range(int(port_min), int((port_max or port_min)) + 1))
                if ports & admin_ports:
                    findings.append(Finding("WORLD_OPEN_ADMIN_PORT", "critical", "network", f"{source_label} exposes admin ports {sorted(ports & admin_ports)} to the public internet."))
                if ports & sensitive_ports:
                    findings.append(Finding("WORLD_OPEN_SENSITIVE_PORT", "high", "network", f"{source_label} exposes sensitive service ports {sorted(ports & sensitive_ports)} to the public internet."))
                if 0 < len(ports) <= 3 and ports.isdisjoint(admin_ports | sensitive_ports):
                    findings.append(Finding("WORLD_OPEN_LIMITED_PORTS", "medium", "network", f"{source_label} exposes ports {min(ports)}-{max(ports)} to the public internet."))

        for nsg_id in row.get("nsg_ids", []):
            for rule in self._get_nsg_rules(region, nsg_id):
                analyze_rule(rule, f"NSG {ocid_last(nsg_id)}")

        for sec_id in row.get("security_list_ids", []):
            sec = self._get_security_list(region, sec_id)
            if not sec:
                continue
            for rule in safe_getattr(sec, "ingress_security_rules", default=[]):
                analyze_rule(rule, f"Security list {ocid_last(sec_id)}")
        return findings

    def _max_severity(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "none"
        ordered = ["critical", "high", "medium", "low", "info"]
        severities = {f["severity"] for f in findings}
        for sev in ordered:
            if sev in severities:
                return sev
        return "none"

    def _build_summary(self, rows: List[Dict[str, Any]], errors: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        severity_counts = Counter(f["severity"] for f in findings)
        code_counts = Counter(f["code"] for f in findings)
        capacity_counts = Counter(r.get("capacity_type") for r in rows)
        utilization_counts = Counter(r.get("utilization_recommendation") for r in rows)
        return {
            "instance_count": len(rows),
            "error_count": len(errors),
            "severity_counts": dict(severity_counts),
            "top_finding_codes": dict(code_counts.most_common(15)),
            "capacity_type_counts": dict(capacity_counts),
            "utilization_recommendation_counts": dict(utilization_counts),
            "security_zone_instance_count": sum(1 for r in rows if r.get("security_zone_name")),
            "public_ip_instance_count": sum(1 for r in rows if r.get("primary_public_ip")),
            "unmanaged_osmh_instance_count": sum(1 for r in rows if r.get("osmh_managed") is False),
            "vss_missing_count": sum(1 for r in rows if not r.get("vss_targeted")),
        }


def render_html_report(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    findings = report.get("findings", [])
    instances = report.get("instances", [])
    errors = report.get("errors", [])
    config = report.get("config", {})

    def badge(label: str, kind: str) -> str:
        return f"<span class='badge badge-{html.escape((kind or 'info').lower())}'>{html.escape(str(label))}</span>"

    def metric_card(label: str, value: Any, hint: str = "") -> str:
        hint_html = f"<div class='hint'>{html.escape(hint)}</div>" if hint else ""
        return (
            "<div class='metric'>"
            f"<div class='label'>{html.escape(label)}</div>"
            f"<div class='value'>{html.escape(str(value))}</div>"
            f"{hint_html}"
            "</div>"
        )

    def yes_no(value: Any) -> str:
        return "Yes" if bool(value) else "No"

    top_codes = [[html.escape(k), str(v)] for k, v in summary.get("top_finding_codes", {}).items()]
    sev_counts = [[badge(k, k), str(v)] for k, v in summary.get("severity_counts", {}).items()]
    cap_counts = [[html.escape(k), str(v)] for k, v in summary.get("capacity_type_counts", {}).items()]
    util_counts = [[html.escape(k), str(v)] for k, v in summary.get("utilization_recommendation_counts", {}).items()]
    config_rows = [
        ["Profile", html.escape(str(config.get("profile", "")))],
        ["Regions scanned", html.escape(", ".join(config.get("regions", []) or []))],
        ["Active only", html.escape(yes_no(config.get("active_only")))],
        ["Agent plugin checks", html.escape(yes_no(config.get("include_agent_plugins")))],
        ["Utilization checks", html.escape(yes_no(config.get("include_utilization")))],
        ["Metrics lookback (hours)", html.escape(str(config.get("metrics_lookback_hours", "")))],
        ["Policy file", html.escape(str(config.get("policy_file") or "default policy"))],
    ]

    critical_rows: List[List[str]] = []
    for row in sorted(instances, key=lambda x: x.get("risk_score", 0), reverse=True)[:50]:
        critical_rows.append(
            [
                html.escape(str(row.get("region", ""))),
                html.escape(str(row.get("compartment_name", ""))),
                html.escape(str(row.get("instance_name", ""))),
                html.escape(str(row.get("shape", ""))),
                badge(str(row.get("highest_severity", "none")), str(row.get("highest_severity", "info"))),
                html.escape(str(row.get("risk_score", ""))),
                html.escape(str(row.get("utilization_recommendation", ""))),
                html.escape(", ".join(row.get("findings", [])[:6])),
            ]
        )

    finding_rows: List[List[str]] = []
    for f in findings[:250]:
        finding_rows.append(
            [
                badge(str(f.get("severity", "info")), str(f.get("severity", "info"))),
                html.escape(str(f.get("category", ""))),
                html.escape(str(f.get("code", ""))),
                html.escape(str(f.get("instance_name", ""))),
                html.escape(str(f.get("message", ""))),
            ]
        )

    instance_rows: List[List[str]] = []
    for row in sorted(instances, key=lambda x: (x.get("highest_severity", ""), x.get("risk_score", 0)), reverse=True)[:200]:
        instance_rows.append(
            [
                html.escape(str(row.get("region", ""))),
                html.escape(str(row.get("compartment_name", ""))),
                html.escape(str(row.get("instance_name", ""))),
                html.escape(str(row.get("state", ""))),
                html.escape(str(row.get("shape", ""))),
                html.escape(str(row.get("primary_private_ip", ""))),
                html.escape(str(row.get("primary_public_ip", "")) if row.get("primary_public_ip") else "-"),
                html.escape(str(row.get("security_zone_name", "")) if row.get("security_zone_name") else "-"),
                html.escape(str(row.get("instance_pool_name", "")) if row.get("instance_pool_name") else "-"),
                html.escape(str(row.get("cpu_avg_pct", "")) if row.get("cpu_avg_pct") is not None else "-"),
                html.escape(str(row.get("memory_avg_pct", "")) if row.get("memory_avg_pct") is not None else "-"),
                badge(str(row.get("highest_severity", "none")), str(row.get("highest_severity", "info"))),
            ]
        )

    error_rows = [
        [
            html.escape(str(e.get("region", ""))),
            html.escape(str(e.get("compartment_name", ""))),
            html.escape(str(e.get("instance_name", ""))),
            html.escape(str(e.get("error", ""))),
        ]
        for e in errors[:150]
    ]

    empty_hint = ""
    if summary.get("instance_count", 0) == 0 and summary.get("error_count", 0) == 0:
        empty_hint = (
            "<div class='callout warning'>"
            "<strong>No instances were audited.</strong> Check the selected region, compartment scope, and authentication context. "
            "This usually means the script scanned the wrong scope rather than that the tenancy is empty."
            "</div>"
        )

    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>OCI Compute Health Check Audit</title>
<style>
:root {{
  --bg: #f8fafc;
  --card: #ffffff;
  --line: #e5e7eb;
  --text: #0f172a;
  --muted: #64748b;
  --thead: #f1f5f9;
  --critical: #991b1b;
  --critical-bg: #fee2e2;
  --high: #9a3412;
  --high-bg: #ffedd5;
  --medium: #92400e;
  --medium-bg: #fef3c7;
  --low: #065f46;
  --low-bg: #d1fae5;
  --info: #1d4ed8;
  --info-bg: #dbeafe;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{ margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 Arial, Helvetica, sans-serif; }}
.container {{ max-width: 1600px; margin: 0 auto; padding: 24px; }}
h1, h2, h3 {{ margin: 0 0 10px; line-height: 1.2; }}
p {{ margin: 0 0 10px; }}
a {{ color: #1d4ed8; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.header {{ display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; flex-wrap: wrap; margin-bottom: 18px; }}
.header-meta {{ color: var(--muted); }}
.nav {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0 22px; }}
.nav a {{ background: #e2e8f0; border-radius: 999px; padding: 7px 12px; font-size: 13px; }}
.card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }}
.metric {{ border: 1px solid var(--line); border-radius: 12px; padding: 14px; background: linear-gradient(180deg, #fff, #f8fafc); min-height: 94px; }}
.metric .label {{ font-size: 12px; color: var(--muted); margin-bottom: 6px; }}
.metric .value {{ font-size: 28px; font-weight: 700; word-break: break-word; }}
.metric .hint {{ margin-top: 6px; color: var(--muted); font-size: 12px; }}
.table-wrap {{ overflow: auto; border: 1px solid var(--line); border-radius: 12px; }}
table {{ width: 100%; border-collapse: collapse; min-width: 760px; }}
th, td {{ border-bottom: 1px solid var(--line); padding: 9px 10px; text-align: left; vertical-align: top; font-size: 13px; }}
th {{ position: sticky; top: 0; background: var(--thead); z-index: 1; white-space: nowrap; }}
tbody tr:nth-child(even) {{ background: #fbfdff; }}
td {{ word-break: break-word; }}
.muted {{ color: var(--muted); }}
.badge {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.02em; white-space: nowrap; }}
.badge-critical {{ color: var(--critical); background: var(--critical-bg); }}
.badge-high {{ color: var(--high); background: var(--high-bg); }}
.badge-medium {{ color: var(--medium); background: var(--medium-bg); }}
.badge-low {{ color: var(--low); background: var(--low-bg); }}
.badge-info {{ color: var(--info); background: var(--info-bg); }}
.two-col {{ display: grid; grid-template-columns: 1.2fr 1fr; gap: 18px; }}
.callout {{ border-radius: 12px; padding: 12px 14px; margin-bottom: 16px; border: 1px solid var(--line); }}
.callout.warning {{ background: #fff7ed; border-color: #fdba74; }}
details summary {{ cursor: pointer; color: var(--muted); margin-bottom: 10px; }}
.footer {{ color: var(--muted); font-size: 12px; margin-top: 10px; }}
@media (max-width: 980px) {{
  .two-col {{ grid-template-columns: 1fr; }}
  .container {{ padding: 14px; }}
  .metric .value {{ font-size: 24px; }}
}}
@media print {{
  body {{ background: #fff; }}
  .nav {{ display: none; }}
  .card {{ box-shadow: none; break-inside: avoid; }}
  th {{ position: static; }}
}}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <div>
      <h1>OCI Compute Health Check Audit</h1>
      <div class='header-meta'>Generated at {html.escape(report['generated_at_utc'])}</div>
      <div class='header-meta'>Project: {html.escape(str(report.get('project', 'oci_compute_health_check_audit')))} · Script: {html.escape(str(report.get('script', 'oci_compute_audit.py')))}</div>
    </div>
    <div class='header-meta'>
      <div>Instances audited: <strong>{summary.get('instance_count', 0)}</strong></div>
      <div>Errors: <strong>{summary.get('error_count', 0)}</strong></div>
    </div>
  </div>

  <div class='nav'>
    <a href='#overview'>Overview</a>
    <a href='#config'>Run config</a>
    <a href='#risk'>Highest risk</a>
    <a href='#findings'>Findings</a>
    <a href='#instances'>Instances</a>
    <a href='#errors'>Errors</a>
  </div>

  {empty_hint}

  <section id='overview' class='card'>
    <h2>Overview</h2>
    <div class='grid'>
      {metric_card('Instances', summary.get('instance_count', 0), 'Compute instances successfully audited')}
      {metric_card('Errors', summary.get('error_count', 0), 'Audit exceptions recorded')}
      {metric_card('Public IP instances', summary.get('public_ip_instance_count', 0), 'Primary VNIC has a public IP')}
      {metric_card('Security zone instances', summary.get('security_zone_instance_count', 0), 'In or under a Security Zone compartment')}
      {metric_card('OSMH unmanaged', summary.get('unmanaged_osmh_instance_count', 0), 'Not seen by OS Management Hub')}
      {metric_card('VSS coverage missing', summary.get('vss_missing_count', 0), 'No vulnerability scanning target resolved')}
    </div>
  </section>

  <div class='two-col'>
    <section id='config' class='card'>
      <h2>Run configuration</h2>
      <div class='table-wrap'>{html_table(['Setting', 'Value'], config_rows)}</div>
    </section>

    <section class='card'>
      <h2>Summary breakdowns</h2>
      <h3>Severity counts</h3>
      <div class='table-wrap'>{html_table(['Severity', 'Count'], sev_counts)}</div>
      <h3 style='margin-top:14px;'>Top finding codes</h3>
      <div class='table-wrap'>{html_table(['Finding code', 'Count'], top_codes)}</div>
      <h3 style='margin-top:14px;'>Capacity types</h3>
      <div class='table-wrap'>{html_table(['Capacity type', 'Count'], cap_counts)}</div>
      <h3 style='margin-top:14px;'>Utilization recommendations</h3>
      <div class='table-wrap'>{html_table(['Recommendation', 'Count'], util_counts)}</div>
    </section>
  </div>

  <section id='risk' class='card'>
    <h2>Highest-risk instances</h2>
    <p class='muted'>Top 50 instances by computed risk score.</p>
    <div class='table-wrap'>{html_table(['Region', 'Compartment', 'Instance', 'Shape', 'Highest severity', 'Risk score', 'Utilization', 'Top findings'], critical_rows)}</div>
  </section>

  <section id='findings' class='card'>
    <h2>Findings sample</h2>
    <p class='muted'>First 250 findings in report order. Use JSON output for the full structured dataset.</p>
    <div class='table-wrap'>{html_table(['Severity', 'Category', 'Code', 'Instance', 'Message'], finding_rows)}</div>
  </section>

  <section id='instances' class='card'>
    <h2>Instance summary</h2>
    <p class='muted'>Top 200 instances sorted by severity and risk score.</p>
    <div class='table-wrap'>{html_table(['Region', 'Compartment', 'Instance', 'State', 'Shape', 'Private IP', 'Public IP', 'Security Zone', 'Instance Pool', 'CPU avg %', 'Memory avg %', 'Highest severity'], instance_rows)}</div>
    <details>
      <summary>Why only a subset is shown here?</summary>
      <p>The HTML report is meant to stay readable. The JSON and CSV outputs contain the complete audit result set.</p>
    </details>
  </section>

  <section id='errors' class='card'>
    <h2>Errors</h2>
    <div class='table-wrap'>{html_table(['Region', 'Compartment', 'Instance', 'Error'], error_rows)}</div>
  </section>

  <div class='footer'>Generated by oci_compute_health_check_audit. For full fidelity and machine-readable details, review the accompanying JSON output.</div>
</div>
</body>
</html>
"""


def write_outputs(report: Dict[str, Any], output_dir: Path, output_prefix: str) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{output_prefix}_{stamp}"
    paths: Dict[str, Path] = {}

    json_path = output_dir / f"{base}.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    paths["json"] = json_path

    csv_fields = [
        "region",
        "compartment_name",
        "instance_name",
        "state",
        "shape",
        "availability_domain",
        "fault_domain",
        "capacity_type",
        "is_preemptible",
        "primary_private_ip",
        "primary_public_ip",
        "subnet_name",
        "security_zone_name",
        "instance_pool_name",
        "autoscaling_enabled",
        "osmh_managed",
        "vss_targeted",
        "imdsv1_disabled",
        "boot_volume_backup_policy",
        "block_volume_count",
        "cpu_avg_pct",
        "memory_avg_pct",
        "disk_iops_read_avg",
        "disk_iops_write_avg",
        "network_in_bytes_avg",
        "network_out_bytes_avg",
        "utilization_recommendation",
        "highest_severity",
        "risk_score",
        "findings",
    ]
    csv_path = output_dir / f"{base}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()
        for row in report["instances"]:
            flat = dict(row)
            flat["findings"] = ",".join(row.get("findings", []))
            writer.writerow({k: flat.get(k) for k in csv_fields})
    paths["csv"] = csv_path

    html_path = output_dir / f"{base}.html"
    html_path.write_text(render_html_report(report), encoding="utf-8")
    paths["html"] = html_path

    return paths


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="OCI compute health check audit for Cloud Shell.")
    p.add_argument("--profile")
    p.add_argument("--region")
    p.add_argument("--region-list", help="Comma-separated region names.")
    p.add_argument("--all-regions", action="store_true")
    p.add_argument("--compartment-id")
    p.add_argument("--output-dir", default=".")
    p.add_argument("--output-prefix", default="oci_compute_health_check_audit")
    p.add_argument("--active-only", action="store_true")
    p.add_argument("--include-terminated", action="store_true")
    p.add_argument("--include-agent-plugins", action="store_true")
    p.add_argument("--disable-utilization", action="store_true")
    p.add_argument("--metrics-lookback-hours", type=int, default=24)
    p.add_argument("--disable-osmh", action="store_true")
    p.add_argument("--disable-vss", action="store_true")
    p.add_argument("--policy-file", help="YAML or JSON file with severity overrides and thresholds.")
    p.add_argument("--verbose", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        audit = OciComputeHealthCheckAudit(args)
        report = audit.run()
        paths = write_outputs(report, Path(args.output_dir), args.output_prefix)
        summary = report["summary"]
        print("=== OCI Compute Health Check Audit ===")
        print(f"Instances audited : {summary['instance_count']}")
        print(f"Errors            : {summary['error_count']}")
        print(f"Severity counts   : {summary['severity_counts']}")
        print(f"Output JSON       : {paths['json']}")
        print(f"Output CSV        : {paths['csv']}")
        print(f"Output HTML       : {paths['html']}")
        return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
