from __future__ import annotations

import html
import json
from pathlib import Path
from xml.etree import ElementTree

from containmentci.models import CheckStatus, RunResult


def render_terminal(run: RunResult) -> str:
    lines = [
        f"ContainmentCI run {run.id}",
        f"Scenario: {run.scenario}",
        f"Identity: {run.identity}",
        "",
    ]
    for check in run.checks:
        first_denial = (
            f"{check.first_denial_seconds:.3f}s" if check.first_denial_seconds is not None else "--"
        )
        proof = f"{check.proof_seconds:.3f}s" if check.proof_seconds is not None else "--"
        timing = f"{first_denial}/{proof}/{check.containment_slo_seconds:.3f}s"
        lines.append(f"{check.target:<28} {check.status.upper():<6} {timing:>23}  {check.message}")
    lines.extend(
        [
            "",
            f"Containment coverage: {run.coverage_percent}%",
            f"Result: {run.status.upper()}",
            f"Evidence mode: {run.evidence_key_mode}",
            f"Evidence signature: {run.signature}",
        ]
    )
    return "\n".join(lines)


def render_html(run: RunResult) -> str:
    rows = []
    for check in run.checks:
        color = "#15803d" if check.status == CheckStatus.PASS else "#b91c1c"
        first_denial = (
            f"{check.first_denial_seconds:.3f}s"
            if check.first_denial_seconds is not None
            else "Not proven"
        )
        proof = f"{check.proof_seconds:.3f}s" if check.proof_seconds is not None else "Not proven"
        rows.append(
            f"""
            <tr>
              <td>{html.escape(check.target)}</td>
              <td>{html.escape(check.provider)}</td>
              <td>{html.escape(check.resource)}</td>
              <td style="color:{color};font-weight:700">{check.status.upper()}</td>
              <td>{first_denial} / {proof} / {check.containment_slo_seconds:.3f}s</td>
              <td>{html.escape(check.proof_mode)}</td>
              <td>{html.escape(check.message)}</td>
            </tr>
            """
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ContainmentCI Summary Report</title>
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
    <div>{html.escape(run.scenario)} &middot; {html.escape(run.identity)} &middot; {run.status.upper()}</div>
  </section>
  <table>
    <thead><tr><th>Target</th><th>Provider</th><th>Resource</th><th>Status</th>
    <th>First denial / proof / SLO</th><th>Proof mode</th><th>Result details</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
  <p><strong>Run ID:</strong> <code>{run.id}</code></p>
  <p><strong>Evidence mode:</strong> <code>{html.escape(run.evidence_key_mode)}</code></p>
  <p><strong>Evidence signature:</strong> <code>{run.signature}</code></p>
</main></body></html>"""


def write_html_report(run: RunResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(run), encoding="utf-8")


def write_json_evidence(run: RunResult, path: Path) -> None:
    """Write the complete signed run and event chain as portable JSON evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(run.model_dump_json(indent=2), encoding="utf-8")


def render_junit(run: RunResult) -> str:
    failures = sum(check.status == CheckStatus.FAIL for check in run.checks)
    errors = sum(check.status == CheckStatus.ERROR for check in run.checks)
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": f"ContainmentCI: {run.scenario}",
            "tests": str(len(run.checks)),
            "failures": str(failures),
            "errors": str(errors),
            "time": f"{sum(check.elapsed_seconds for check in run.checks):.3f}",
            "timestamp": run.started_at.isoformat(),
        },
    )
    properties = ElementTree.SubElement(suite, "properties")
    for name, value in (
        ("identity", run.identity),
        ("coverage_percent", run.coverage_percent),
        ("evidence_key_mode", run.evidence_key_mode),
        ("evidence_signature", run.signature),
    ):
        ElementTree.SubElement(properties, "property", {"name": name, "value": str(value)})
    for check in run.checks:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": f"containmentci.{check.provider}",
                "name": check.target,
                "time": f"{check.elapsed_seconds:.3f}",
            },
        )
        if check.status == CheckStatus.FAIL:
            failure = ElementTree.SubElement(
                case, "failure", {"message": check.message, "type": "containment-failure"}
            )
            failure.text = json.dumps(check.evidence, sort_keys=True, default=str)
        elif check.status == CheckStatus.ERROR:
            error = ElementTree.SubElement(
                case, "error", {"message": check.message, "type": "containment-error"}
            )
            error.text = json.dumps(check.evidence, sort_keys=True, default=str)
        output = ElementTree.SubElement(case, "system-out")
        output.text = (
            f"proof_mode={check.proof_mode}\n"
            f"first_denial_seconds={check.first_denial_seconds}\n"
            f"proof_seconds={check.proof_seconds}\n"
            f"slo_seconds={check.containment_slo_seconds}\n"
            f"denial_confirmations={check.denial_confirmations}"
        )
    ElementTree.indent(suite)
    return ElementTree.tostring(suite, encoding="unicode", xml_declaration=True)


def write_junit_report(run: RunResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_junit(run), encoding="utf-8")
