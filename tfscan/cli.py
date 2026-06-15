"""Command-line interface for TFSCAN."""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone

from . import TOOL_NAME, TOOL_VERSION
from .core import ScanResult, Severity, scan_path

_SEV_COLOR = {
    "CRITICAL": "#b3001b",
    "HIGH": "#d9480f",
    "MEDIUM": "#b08900",
    "LOW": "#2b6cb0",
}


def _render_table(result: ScanResult) -> str:
    lines: list[str] = []
    c = result.counts
    lines.append(
        f"Scanned {result.files_scanned} file(s), "
        f"{result.resources_scanned} resource(s)"
    )
    lines.append(
        "Findings: "
        f"CRITICAL={c['CRITICAL']} HIGH={c['HIGH']} "
        f"MEDIUM={c['MEDIUM']} LOW={c['LOW']} "
        f"(total {len(result.findings)})"
    )
    lines.append("")
    if not result.findings:
        lines.append("No misconfigurations found.")
    else:
        hdr = f"{'SEVERITY':<9} {'CHECK':<7} {'RESOURCE':<32} LOCATION"
        lines.append(hdr)
        lines.append("-" * len(hdr))
        for f in result.findings:
            res = f"{f.resource_type}.{f.resource_name}"
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"{f.severity:<9} {f.check_id:<7} {res[:32]:<32} {loc}")
            lines.append(f"    {f.title}")
            lines.append(f"    fix: {f.remediation}")
    for err in result.errors:
        lines.append(f"! {err}")
    return "\n".join(lines)


def _render_html(result: ScanResult) -> str:
    c = result.counts
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for f in result.findings:
        color = _SEV_COLOR.get(f.severity, "#555")
        rows.append(
            "<tr>"
            f'<td><span class="badge" style="background:{color}">{html.escape(f.severity)}</span></td>'
            f"<td class=mono>{html.escape(f.check_id)}</td>"
            f"<td class=mono>{html.escape(f.resource_type)}.{html.escape(f.resource_name)}</td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td class=mono>{html.escape((f.file or '') + (':' + str(f.line) if f.line else ''))}</td>"
            f"<td>{html.escape(f.remediation)}</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan=6 class=ok>No misconfigurations found.</td></tr>')
    summary_cells = "".join(
        f'<div class="sumcard" style="border-color:{_SEV_COLOR[s]}">'
        f'<div class="sumnum" style="color:{_SEV_COLOR[s]}">{c[s]}</div>'
        f'<div class="sumlbl">{s}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    err_html = ""
    if result.errors:
        items = "".join(f"<li>{html.escape(e)}</li>" for e in result.errors)
        err_html = f'<div class="errors"><h3>Errors</h3><ul>{items}</ul></div>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
    margin:0;background:#f5f6f8;color:#1a1a1a}}
  header{{background:#0b1f33;color:#fff;padding:20px 28px}}
  header h1{{margin:0;font-size:20px}}
  header .meta{{opacity:.8;font-size:13px;margin-top:4px}}
  main{{padding:24px 28px;max-width:1200px;margin:0 auto}}
  .summary{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px}}
  .sumcard{{background:#fff;border-left:5px solid;border-radius:8px;
    padding:12px 20px;min-width:96px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
  .sumnum{{font-size:28px;font-weight:700;line-height:1}}
  .sumlbl{{font-size:12px;color:#666;margin-top:4px;letter-spacing:.04em}}
  .scanmeta{{color:#555;font-size:13px;margin:10px 0 18px}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
    overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
  th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #eee;
    font-size:13px;vertical-align:top}}
  th{{background:#f0f2f5;font-size:11px;text-transform:uppercase;
    letter-spacing:.05em;color:#555}}
  tr:last-child td{{border-bottom:none}}
  .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;
    font-weight:700;letter-spacing:.03em}}
  .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:12px}}
  .ok{{text-align:center;color:#2f855a;font-weight:600;padding:18px}}
  .errors{{margin-top:20px;color:#b3001b;font-size:13px}}
  footer{{padding:18px 28px;color:#888;font-size:12px;text-align:center}}
</style></head>
<body>
<header>
  <h1>{TOOL_NAME} &middot; Terraform misconfiguration report</h1>
  <div class="meta">Generated {ts} &middot; v{TOOL_VERSION}</div>
</header>
<main>
  <div class="summary">{summary_cells}</div>
  <div class="scanmeta">Scanned {result.files_scanned} file(s) and
    {result.resources_scanned} resource(s) &middot;
    {len(result.findings)} finding(s)</div>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Resource</th>
      <th>Title</th><th>Location</th><th>Remediation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  {err_html}
</main>
<footer>{TOOL_NAME} v{TOOL_VERSION} &middot; defensive IaC misconfig gate</footer>
</body></html>
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan Terraform plans/configs for misconfigurations "
        "(defensive IaC misconfig gate).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="Scan a file or directory of .tf/.tf.json/plan files")
    sp.add_argument("path", help="File or directory to scan")
    sp.add_argument("--format", choices=["table", "json", "html"],
                    default="table", help="Output format")
    sp.add_argument("-o", "--output", help="Write report to file instead of stdout")
    sp.add_argument("--min-severity", choices=[s.value for s in Severity],
                    help="Only report findings at or above this severity")
    return p


def _filter_severity(result: ScanResult, min_sev: str | None) -> ScanResult:
    if not min_sev:
        return result
    floor = Severity(min_sev).rank
    result.findings = [f for f in result.findings
                       if Severity(f.severity).rank >= floor]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    # Validate the path before handing it to the scanner so the user gets a
    # clear message instead of a silent empty result.
    import os as _os
    if not args.path or not args.path.strip():
        print("error: path argument must not be empty", file=sys.stderr)
        return 2
    if not _os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    try:
        result = scan_path(args.path)
    except Exception as exc:  # pragma: no cover
        print(f"error: unexpected failure during scan: {exc}", file=sys.stderr)
        return 2

    result = _filter_severity(result, args.min_severity)

    if args.format == "json":
        out = json.dumps(result.to_dict(), indent=2)
    elif args.format == "html":
        out = _render_html(result)
    else:
        out = _render_table(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
            print(f"Report written to {args.output}", file=sys.stderr)
        except OSError as e:
            print(f"error: cannot write {args.output}: {e}", file=sys.stderr)
            return 2
    else:
        print(out)

    if result.errors:
        return 2
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
