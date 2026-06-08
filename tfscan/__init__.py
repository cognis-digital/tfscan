"""TFSCAN - Terraform plan/config misconfiguration scanner.

Defensive IaC misconfig gate in the spirit of tfsec/checkov.
Standard library only, zero install.
"""
from .core import (
    Finding,
    ScanResult,
    Severity,
    scan_path,
    scan_text,
    load_checks,
)

TOOL_NAME = "tfscan"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "scan_path",
    "scan_text",
    "load_checks",
    "TOOL_NAME",
    "TOOL_VERSION",
]
