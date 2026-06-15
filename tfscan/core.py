"""Core scanning engine for TFSCAN.

Parses Terraform HCL configs (.tf) and JSON plan files (terraform show -json,
or .tf.json) into a normalized resource model, then runs a set of defensive
misconfiguration checks against each resource.

No third-party dependencies. The HCL parser here is intentionally lightweight:
it handles the common subset of HCL used in resource blocks (blocks, nested
blocks, scalar attributes, lists) which is sufficient for misconfig gating.
For exact fidelity, feed in `terraform show -json` plan JSON.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Iterable


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    resource_type: str
    resource_name: str
    file: str
    line: int
    message: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Resource:
    rtype: str
    name: str
    attrs: dict[str, Any]
    file: str = ""
    line: int = 0


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    resources_scanned: int = 0
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "resources_scanned": self.resources_scanned,
            "counts": self.counts,
            "total_findings": len(self.findings),
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"(#|//).*$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT_RE.sub("", text)
    text = _COMMENT_RE.sub("", text)
    return text


def _coerce(token: str) -> Any:
    t = token.strip()
    if not t:
        return ""
    if t.startswith('"') and t.endswith('"') and len(t) >= 2:
        return t[1:-1]
    low = t.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_coerce(x) for x in _split_top_level(inner, ",")]
    return t  # raw expression / reference


def _split_top_level(s: str, sep: str) -> list[str]:
    out, depth, buf, instr = [], 0, [], False
    for ch in s:
        if ch == '"':
            instr = not instr
        if not instr:
            if ch in "[{(":
                depth += 1
            elif ch in "]})":
                depth -= 1
            elif ch == sep and depth == 0:
                out.append("".join(buf))
                buf = []
                continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [x.strip() for x in out if x.strip()]


def _parse_body(lines: list[str], i: int, line_off: int) -> tuple[dict[str, Any], int]:
    """Parse a `{ ... }` body starting after the opening brace.

    Returns (attrs, next_index). Nested blocks accumulate into lists so that
    e.g. multiple `ingress {}` blocks become attrs['ingress'] = [..., ...].
    """
    attrs: dict[str, Any] = {}
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.strip()
        if line == "}" or line.endswith("}") and "{" not in line and "=" not in line:
            return attrs, i + 1
        if not line:
            i += 1
            continue
        # nested block:  name {   OR   name "label" {
        m_block = re.match(r'^([A-Za-z0-9_-]+)(?:\s+"[^"]*")?\s*\{\s*$', line)
        if m_block:
            key = m_block.group(1)
            child, i = _parse_body(lines, i + 1, line_off)
            attrs.setdefault(key, [])
            if not isinstance(attrs[key], list):
                attrs[key] = [attrs[key]]
            attrs[key].append(child)
            continue
        # attribute = value   (value may span brackets on one line)
        m_attr = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$', line)
        if m_attr:
            key, val = m_attr.group(1), m_attr.group(2)
            # multi-line list / heredoc-ish: keep consuming until balanced
            if val.count("[") > val.count("]"):
                while i + 1 < n and val.count("[") > val.count("]"):
                    i += 1
                    val += " " + lines[i].strip()
            attrs[key] = _coerce(val)
            i += 1
            continue
        i += 1
    return attrs, i


def parse_hcl(text: str, filename: str = "") -> list[Resource]:
    """Parse resource blocks out of an HCL document."""
    text = _strip_comments(text)
    lines = text.split("\n")
    resources: list[Resource] = []
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i].strip()
        m = re.match(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{\s*$', line)
        if m:
            rtype, name = m.group(1), m.group(2)
            attrs, i = _parse_body(lines, i + 1, i)
            resources.append(Resource(rtype, name, attrs, filename, i))
            continue
        i += 1
    return resources


def parse_plan_json(text: str, filename: str = "") -> list[Resource]:
    """Parse `terraform show -json` plan output or a .tf.json document."""
    if not text or not text.strip():
        raise ValueError("empty JSON input")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(
            f"expected a JSON object at top level, got {type(data).__name__}"
        )
    resources: list[Resource] = []

    def walk_module(mod: dict[str, Any]) -> None:
        if not isinstance(mod, dict):
            return
        for r in mod.get("resources", []) or []:
            if not isinstance(r, dict):
                continue
            rtype = r.get("type", "") or ""
            name = r.get("name", "") or ""
            vals = r.get("values", r.get("expressions", {})) or {}
            if not isinstance(vals, dict):
                vals = {}
            resources.append(Resource(rtype, name, vals, filename, 0))
        for child in mod.get("child_modules", []) or []:
            walk_module(child)

    # terraform show -json layout
    if "planned_values" in data or "values" in data:
        root = data.get("planned_values", data.get("values", {}))
        rm = root.get("root_module", {})
        walk_module(rm)
        return resources
    # resource_changes layout
    if "resource_changes" in data:
        for rc in data["resource_changes"]:
            after = (rc.get("change", {}) or {}).get("after", {}) or {}
            resources.append(
                Resource(rc.get("type", ""), rc.get("name", ""), after, filename, 0)
            )
        return resources
    # plain .tf.json: { "resource": { type: { name: {...} } } }
    if "resource" in data and isinstance(data["resource"], dict):
        for rtype, byname in data["resource"].items():
            if isinstance(byname, dict):
                for name, body in byname.items():
                    body = body[0] if isinstance(body, list) and body else body
                    resources.append(
                        Resource(rtype, name, body or {}, filename, 0)
                    )
        return resources
    return resources


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

def _as_blocks(v: Any) -> list[dict[str, Any]]:
    if isinstance(v, list):
        return [b for b in v if isinstance(b, dict)]
    if isinstance(v, dict):
        return [v]
    return []


def _truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


@dataclass
class Check:
    check_id: str
    title: str
    severity: Severity
    applies_to: str  # resource type, or "*"
    remediation: str
    fn: Callable[[Resource], bool]  # returns True if VIOLATION found
    message: str = ""


def _open_to_world(block: dict[str, Any]) -> bool:
    cidrs = block.get("cidr_blocks", [])
    if isinstance(cidrs, str):
        cidrs = [cidrs]
    v6 = block.get("ipv6_cidr_blocks", [])
    if isinstance(v6, str):
        v6 = [v6]
    return "0.0.0.0/0" in (cidrs or []) or "::/0" in (v6 or [])


def load_checks() -> list[Check]:
    """Built-in defensive misconfiguration checks (AWS-focused subset)."""
    checks: list[Check] = []

    def add(cid, title, sev, applies, rem, fn, msg=""):
        checks.append(Check(cid, title, sev, applies, rem, fn, msg))

    # S3 public access / encryption
    add(
        "TFS001", "S3 bucket ACL grants public access", Severity.CRITICAL,
        "aws_s3_bucket",
        "Set acl = \"private\" and use aws_s3_bucket_public_access_block.",
        lambda r: r.attrs.get("acl") in ("public-read", "public-read-write"),
        "Bucket ACL exposes objects publicly.",
    )
    add(
        "TFS002", "S3 bucket missing server-side encryption", Severity.HIGH,
        "aws_s3_bucket",
        "Add a server_side_encryption_configuration block (aws:kms or AES256).",
        lambda r: not r.attrs.get("server_side_encryption_configuration"),
        "No default encryption configured for bucket.",
    )
    add(
        "TFS003", "S3 public access block disabled", Severity.HIGH,
        "aws_s3_bucket_public_access_block",
        "Set all four block_public_* / restrict_public_* flags to true.",
        lambda r: not all(
            _truthy(r.attrs.get(k, False))
            for k in (
                "block_public_acls", "block_public_policy",
                "ignore_public_acls", "restrict_public_buckets",
            )
        ),
        "One or more public-access-block flags is not enabled.",
    )

    # Security group ingress open to world
    def sg_open(r: Resource) -> bool:
        for blk in _as_blocks(r.attrs.get("ingress")):
            if _open_to_world(blk):
                return True
        return False

    add(
        "TFS010", "Security group allows ingress from 0.0.0.0/0", Severity.HIGH,
        "aws_security_group",
        "Restrict cidr_blocks to known IP ranges; avoid 0.0.0.0/0.",
        sg_open,
        "Ingress rule open to the entire internet.",
    )

    def sg_rule_open(r: Resource) -> bool:
        if r.attrs.get("type") != "ingress":
            return False
        return _open_to_world(r.attrs)

    add(
        "TFS011", "SG rule allows ingress from 0.0.0.0/0", Severity.HIGH,
        "aws_security_group_rule",
        "Restrict cidr_blocks on ingress rules to known ranges.",
        sg_rule_open,
        "Ingress security-group rule open to the internet.",
    )

    def ssh_rdp_open(r: Resource) -> bool:
        blocks = _as_blocks(r.attrs.get("ingress"))
        if r.rtype == "aws_security_group_rule" and r.attrs.get("type") == "ingress":
            blocks = [r.attrs]
        for blk in blocks:
            if not _open_to_world(blk):
                continue
            fp, tp = blk.get("from_port"), blk.get("to_port")
            for port in (22, 3389):
                try:
                    if fp is not None and tp is not None and int(fp) <= port <= int(tp):
                        return True
                except (TypeError, ValueError):
                    pass
        return False

    add(
        "TFS012", "SSH/RDP exposed to the internet", Severity.CRITICAL,
        "aws_security_group",
        "Never expose 22/3389 to 0.0.0.0/0; use a bastion or VPN.",
        ssh_rdp_open,
        "Port 22 or 3389 reachable from 0.0.0.0/0.",
    )
    add(
        "TFS013", "SSH/RDP exposed to the internet", Severity.CRITICAL,
        "aws_security_group_rule",
        "Never expose 22/3389 to 0.0.0.0/0; use a bastion or VPN.",
        ssh_rdp_open,
        "Port 22 or 3389 reachable from 0.0.0.0/0.",
    )

    # RDS
    add(
        "TFS020", "RDS instance is publicly accessible", Severity.HIGH,
        "aws_db_instance",
        "Set publicly_accessible = false.",
        lambda r: _truthy(r.attrs.get("publicly_accessible", False)),
        "Database instance is internet-reachable.",
    )
    add(
        "TFS021", "RDS storage not encrypted", Severity.HIGH,
        "aws_db_instance",
        "Set storage_encrypted = true.",
        lambda r: not _truthy(r.attrs.get("storage_encrypted", False)),
        "RDS storage encryption is disabled.",
    )

    # EBS
    add(
        "TFS030", "EBS volume not encrypted", Severity.MEDIUM,
        "aws_ebs_volume",
        "Set encrypted = true.",
        lambda r: not _truthy(r.attrs.get("encrypted", False)),
        "EBS volume encryption is disabled.",
    )

    # IAM wildcard policy (heuristic on inline policy json string)
    def iam_wildcard(r: Resource) -> bool:
        pol = r.attrs.get("policy") or r.attrs.get("assume_role_policy") or ""
        if not isinstance(pol, str):
            pol = json.dumps(pol)
        return '"Action": "*"' in pol or '"Action":"*"' in pol or (
            '"*"' in pol and '"Resource": "*"' in pol
        )

    add(
        "TFS040", "IAM policy grants wildcard (*) permissions", Severity.HIGH,
        "aws_iam_policy",
        "Scope Action and Resource to least privilege; avoid \"*\".",
        iam_wildcard,
        "Policy document uses wildcard Action/Resource.",
    )
    add(
        "TFS041", "IAM role policy grants wildcard (*) permissions", Severity.HIGH,
        "aws_iam_role_policy",
        "Scope Action and Resource to least privilege; avoid \"*\".",
        iam_wildcard,
        "Role policy document uses wildcard Action/Resource.",
    )

    # Unencrypted SNS/SQS
    add(
        "TFS050", "SQS queue not encrypted", Severity.MEDIUM,
        "aws_sqs_queue",
        "Set kms_master_key_id or sqs_managed_sse_enabled = true.",
        lambda r: not r.attrs.get("kms_master_key_id")
        and not _truthy(r.attrs.get("sqs_managed_sse_enabled", False)),
        "SQS queue lacks server-side encryption.",
    )

    # CloudTrail log validation
    add(
        "TFS060", "CloudTrail log file validation disabled", Severity.MEDIUM,
        "aws_cloudtrail",
        "Set enable_log_file_validation = true.",
        lambda r: not _truthy(r.attrs.get("enable_log_file_validation", False)),
        "CloudTrail integrity validation is off.",
    )

    return checks


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _run_checks(resources: list[Resource], checks: list[Check]) -> list[Finding]:
    findings: list[Finding] = []
    for r in resources:
        for chk in checks:
            if chk.applies_to != "*" and chk.applies_to != r.rtype:
                continue
            try:
                if chk.fn(r):
                    findings.append(
                        Finding(
                            check_id=chk.check_id,
                            title=chk.title,
                            severity=chk.severity.value,
                            resource_type=r.rtype,
                            resource_name=r.name,
                            file=r.file,
                            line=r.line,
                            message=chk.message or chk.title,
                            remediation=chk.remediation,
                        )
                    )
            except Exception:  # a single check must never abort the scan
                continue
    findings.sort(key=lambda f: (-Severity(f.severity).rank, f.check_id))
    return findings


def scan_text(text: str, filename: str = "<text>", as_json: bool | None = None) -> ScanResult:
    """Scan a single document's text."""
    if text is None:
        text = ""
    checks = load_checks()
    is_json = as_json
    if is_json is None:
        is_json = filename.endswith(".json") or text.lstrip().startswith("{")
    res = ScanResult(files_scanned=1)
    try:
        resources = parse_plan_json(text, filename) if is_json else parse_hcl(text, filename)
    except Exception as e:
        res.errors.append(f"{filename}: parse error: {e}")
        return res
    res.resources_scanned = len(resources)
    res.findings = _run_checks(resources, checks)
    return res


def _iter_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        yield path
        return
    if not os.path.isdir(path):
        return  # caller checks existence before calling; yields nothing safely
    for root, _dirs, files in os.walk(path):
        for fn in sorted(files):  # deterministic order
            if fn.endswith((".tf", ".tf.json")) or fn.endswith(".json"):
                yield os.path.join(root, fn)


def scan_path(path: str) -> ScanResult:
    """Scan a file or directory tree of Terraform configs/plans."""
    if not path or not path.strip():
        result = ScanResult()
        result.errors.append("scan_path: path must not be empty")
        return result
    if not os.path.exists(path):
        result = ScanResult()
        result.errors.append(f"path not found: {path}")
        return result
    checks = load_checks()
    agg = ScanResult()
    for fpath in _iter_files(path):
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            agg.errors.append(f"{fpath}: {e}")
            continue
        is_json = fpath.endswith(".json")
        try:
            resources = (
                parse_plan_json(text, fpath) if is_json else parse_hcl(text, fpath)
            )
        except Exception as e:
            agg.errors.append(f"{fpath}: parse error: {e}")
            continue
        agg.files_scanned += 1
        agg.resources_scanned += len(resources)
        agg.findings.extend(_run_checks(resources, checks))
    agg.findings.sort(key=lambda f: (-Severity(f.severity).rank, f.check_id, f.file))
    return agg
