"""
DexRipper - Report Generator

Generates JSON or HTML reports from DEX validation results.
"""

import json
import os
import time
from typing import List, Dict


def generate_report(results: List[Dict], fmt: str = "json") -> str:
    """Generate a report in the specified format."""
    if fmt == "json":
        return _generate_json(results)
    elif fmt == "html":
        return _generate_html(results)
    else:
        return _generate_json(results)


def _generate_json(results: List[Dict]) -> str:
    """Generate JSON report."""
    report = {
        "tool": "DexRipper",
        "version": "1.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "summary": _compute_summary(results),
        "files": [],
    }

    for r in results:
        report["files"].append({
            "name": os.path.basename(r["path"]),
            "path": r["path"],
            "size": r["size"],
            "status": r.get("status_str", str(r["status"])),
            "adler_ok": r["adler_ok"],
            "class_count": r["class_count"],
            "method_count": r["method_count"],
            "string_count": r["string_count"],
            "type_count": r["type_count"],
            "version": r.get("version", ""),
            "sha256": r.get("sha256", ""),
        })

    return json.dumps(report, indent=2, ensure_ascii=False)


def _generate_html(results: List[Dict]) -> str:
    """Generate HTML report."""
    summary = _compute_summary(results)

    rows = ""
    for r in results:
        name = os.path.basename(r["path"])
        size = r["size"]
        size_str = f"{size/1024:.0f}K" if size < 1024*1024 else f"{size/1024/1024:.1f}M"
        adler = "OK" if r["adler_ok"] else "FAIL"
        status = r.get("status_str", str(r["status"]))
        status_class = "valid" if r["status"] == 0 else "invalid"
        classes = r["class_count"]
        methods = r["method_count"]
        sha = r.get("sha256", "")[:16]

        rows += f"""        <tr class="{status_class}">
          <td>{name}</td>
          <td>{size_str}</td>
          <td>{adler}</td>
          <td>{classes}</td>
          <td>{methods}</td>
          <td>{sha}</td>
          <td><span class="badge {status_class}">{status}</span></td>
        </tr>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DexRipper Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
    h1 {{ color: #e94560; }}
    .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
    .stat {{ background: #16213e; padding: 15px 25px; border-radius: 8px; text-align: center; }}
    .stat .num {{ font-size: 2em; font-weight: bold; color: #e94560; }}
    .stat .label {{ color: #999; font-size: 0.9em; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th {{ background: #16213e; color: #e94560; padding: 10px; text-align: left; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #333; font-family: monospace; font-size: 0.9em; }}
    tr:hover {{ background: #16213e; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
    .badge.valid {{ background: #0f3460; color: #4ecca3; }}
    .badge.invalid {{ background: #3d0000; color: #e94560; }}
    .footer {{ margin-top: 20px; color: #666; font-size: 0.8em; }}
  </style>
</head>
<body>
  <h1>DexRipper Report</h1>
  <p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>

  <div class="summary">
    <div class="stat"><div class="num">{summary['total']}</div><div class="label">Total</div></div>
    <div class="stat"><div class="num">{summary['valid']}</div><div class="label">Valid</div></div>
    <div class="stat"><div class="num">{summary['invalid']}</div><div class="label">Invalid</div></div>
    <div class="stat"><div class="num">{summary['total_mb']}MB</div><div class="label">Size</div></div>
  </div>

  <table>
    <thead>
      <tr><th>File</th><th>Size</th><th>Adler</th><th>Classes</th><th>Methods</th><th>SHA-256</th><th>Status</th></tr>
    </thead>
    <tbody>
{rows}    </tbody>
  </table>

  <div class="footer">DexRipper v1.0.0 - Android DEX Unpacking Toolkit</div>
</body>
</html>"""


def _compute_summary(results: List[Dict]) -> Dict:
    """Compute summary statistics."""
    total = len(results)
    valid = sum(1 for r in results if r["status"] == 0)
    invalid = total - valid
    total_size = sum(r["size"] for r in results)
    return {
        "total": total,
        "valid": valid,
        "invalid": invalid,
        "total_mb": round(total_size / 1024 / 1024, 1),
    }
