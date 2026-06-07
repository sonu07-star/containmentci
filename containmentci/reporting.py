from __future__ import annotations

import html
from pathlib import Path

from containmentci.models import CheckStatus, RunResult


def render_terminal(run: RunResult) -> str:
    lines = [
        f"ContainmentCI run {run.id}",
        f"Scenario: {run.scenario}",
        f"Identity: {run.identity}",
        "",
    ]
    for check in run.checks:
        lines.append(
            f"{check.target:<28} {check.status.upper():<6} "
            f"{check.elapsed_seconds:>7.3f}s  {check.message}"
        )
    lines.extend(
        [
            "",
            f"Containment coverage: {run.coverage_percent}%",
            f"Result: {run.status.upper()}",
            f"Evidence signature: {run.signature}",
        ]
    )
    return "\n".join(lines)


def render_html(run: RunResult) -> str:
    rows = []
    for check in run.checks:
        color = "#15803d" if check.status == CheckStatus.PASS else "#b91c1c"
        rows.append(
            f"""
            <tr>
              <td>{html.escape(check.target)}</td>
              <td>{html.escape(check.provider)}</td>
              <td>{html.escape(check.resource)}</td>
              <td style="color:{color};font-weight:700">{check.status.upper()}</td>
              <td>{check.elapsed_seconds:.3f}s</td>
              <td>{html.escape(check.message)}</td>
            </tr>
            """
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ContainmentCI Evidence Report</title>
  <style>
    body {{ font: 15px system-ui; margin: 0; background:#f8fafc; color:#0f172a }}
    main {{ max-width:1100px; margin:40px auto; padding:0 20px }}
    .hero {{ background:#0f172a; color:white; padding:28px; border-radius:14px }}
    .score {{ font-size:48px; font-weight:800 }}
    table {{ width:100%; border-collapse:collapse; margin-top:24px; background:white }}
    th,td {{ padding:12px; border-bottom:1px solid #e2e8f0; text-align:left }}
    code {{ word-break:break-all }}
  </style>
</head>
<body><main>
  <section class="hero">
    <div>Containment coverage</div>
    <div class="score">{run.coverage_percent}%</div>
    <div>{html.escape(run.scenario)} · {html.escape(run.identity)} · {run.status.upper()}</div>
  </section>
  <table>
    <thead><tr><th>Target</th><th>Provider</th><th>Resource</th><th>Status</th>
    <th>Time</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <p><strong>Run ID:</strong> <code>{run.id}</code></p>
  <p><strong>Evidence signature:</strong> <code>{run.signature}</code></p>
</main></body></html>"""


def write_html_report(run: RunResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(run), encoding="utf-8")

