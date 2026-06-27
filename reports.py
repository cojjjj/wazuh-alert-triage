from datetime import datetime
from pathlib import Path
import html


def risk_level(score):
    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def risk_color(score):
    if score >= 75:
        return "#ef4444"
    if score >= 40:
        return "#f59e0b"
    if score > 0:
        return "#22c55e"
    return "#64748b"


def generate_markdown_report(alerts, findings, risk_score, mitre_hits, timeline):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / "incident-report.md"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# Wazuh Alert Triage Report",
        "",
        f"**Generated:** {now}",
        "",
        "## Executive Summary",
        "",
        f"- **Total Alerts Analyzed:** {len(alerts)}",
        f"- **Risk Score:** {risk_score}/100",
        f"- **Risk Level:** {risk_level(risk_score)}",
        f"- **Threat Findings:** {len(findings)}",
        f"- **MITRE Techniques Observed:** {len(mitre_hits)}",
        "",
        "## Threat Findings",
        "",
    ]

    if findings:
        lines.append("| Process | Reason | MITRE ATT&CK |")
        lines.append("|---|---|---|")
        for finding in findings:
            lines.append(
                f"| `{finding['process']}` | {finding['reason']} | {finding['mitre']} |"
            )
    else:
        lines.append("No suspicious activity detected.")

    lines.extend(["", "## MITRE ATT&CK Summary", ""])

    if mitre_hits:
        lines.append("| Technique | Count |")
        lines.append("|---|---:|")
        for technique, count in mitre_hits.items():
            lines.append(f"| {technique} | {count} |")
    else:
        lines.append("No MITRE techniques detected.")

    lines.extend(["", "## Investigation Timeline", ""])

    if timeline:
        lines.append("| Time | Agent | Event ID | Process |")
        lines.append("|---|---|---|---|")
        for event in timeline[:50]:
            lines.append(
                f"| {event['time']} | {event['agent']} | {event['event']} | `{event['process']}` |"
            )
    else:
        lines.append("No timeline events available.")

    lines.extend([
        "",
        "## Analyst Notes",
        "",
        "- Review suspicious process executions.",
        "- Validate PowerShell command activity.",
        "- Correlate timeline with endpoint activity.",
        "- Investigate any unexpected MITRE ATT&CK techniques.",
        "",
    ])

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def generate_html_report(alerts, findings, risk_score, mitre_hits, timeline, iocs):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / "incident-report.html"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level = risk_level(risk_score)
    color = risk_color(risk_score)

    finding_rows = ""
    if findings:
        for finding in findings:
            finding_rows += f"""
            <tr>
                <td><code>{html.escape(str(finding["process"]))}</code></td>
                <td>{html.escape(str(finding["reason"]))}</td>
                <td>{html.escape(str(finding["mitre"]))}</td>
            </tr>
            """
    else:
        finding_rows = """
        <tr>
            <td colspan="3">No suspicious activity detected.</td>
        </tr>
        """

    mitre_rows = ""
    if mitre_hits:
        for technique, count in mitre_hits.items():
            mitre_rows += f"""
            <tr>
                <td>{html.escape(str(technique))}</td>
                <td>{count}</td>
            </tr>
            """
    else:
        mitre_rows = """
        <tr>
            <td colspan="2">No MITRE techniques detected.</td>
        </tr>
        """

    timeline_rows = ""
    if timeline:
        for event in timeline[:50]:
            timeline_rows += f"""
            <tr>
                <td>{html.escape(str(event["time"]))}</td>
                <td>{html.escape(str(event["agent"]))}</td>
                <td>{html.escape(str(event["event"]))}</td>
                <td><code>{html.escape(str(event["process"]))}</code></td>
            </tr>
            """
    else:
        timeline_rows = """
        <tr>
            <td colspan="4">No timeline events available.</td>
        </tr>
        """

    ioc_rows = ""
    for ioc_type, values in iocs.items():
        if values:
            for value in values:
                ioc_rows += f"""
                <tr>
                    <td>{html.escape(str(ioc_type))}</td>
                    <td><code>{html.escape(str(value))}</code></td>
                </tr>
                """

    if not ioc_rows:
        ioc_rows = """
        <tr>
            <td colspan="2">No IOCs extracted.</td>
        </tr>
        """

    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wazuh Alert Triage Report</title>
    <style>
        body {{
            background: #0f172a;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}

        .container {{
            max-width: 1100px;
            margin: auto;
        }}

        .header {{
            border: 1px solid #334155;
            border-radius: 14px;
            padding: 24px;
            background: linear-gradient(135deg, #111827, #1e293b);
            margin-bottom: 24px;
        }}

        h1 {{
            margin: 0;
            color: #38bdf8;
            font-size: 34px;
        }}

        .subtitle {{
            color: #94a3b8;
            margin-top: 8px;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}

        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 18px;
        }}

        .card-title {{
            color: #94a3b8;
            font-size: 13px;
            text-transform: uppercase;
        }}

        .card-value {{
            font-size: 28px;
            margin-top: 10px;
            font-weight: bold;
        }}

        .risk-bar {{
            background: #334155;
            border-radius: 999px;
            overflow: hidden;
            height: 16px;
            margin-top: 12px;
        }}

        .risk-fill {{
            width: {risk_score}%;
            background: {color};
            height: 100%;
        }}

        section {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}

        h2 {{
            margin-top: 0;
            color: #38bdf8;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}

        th, td {{
            border-bottom: 1px solid #334155;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            color: #93c5fd;
            background: #1e293b;
        }}

        code {{
            color: #facc15;
        }}

        .badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            background: {color};
            color: #020617;
            font-weight: bold;
        }}

        .footer {{
            color: #64748b;
            text-align: center;
            margin-top: 30px;
        }}

        @media (max-width: 900px) {{
            .cards {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 600px) {{
            .cards {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Wazuh Alert Triage Report</h1>
            <div class="subtitle">Generated: {html.escape(now)}</div>
            <div class="subtitle">Automated security alert summary and investigation report.</div>
        </div>

        <div class="cards">
            <div class="card">
                <div class="card-title">Alerts Analyzed</div>
                <div class="card-value">{len(alerts)}</div>
            </div>

            <div class="card">
                <div class="card-title">Risk Score</div>
                <div class="card-value">{risk_score}/100</div>
                <div class="risk-bar"><div class="risk-fill"></div></div>
            </div>

            <div class="card">
                <div class="card-title">Risk Level</div>
                <div class="card-value"><span class="badge">{level}</span></div>
            </div>

            <div class="card">
                <div class="card-title">Threat Findings</div>
                <div class="card-value">{len(findings)}</div>
            </div>
        </div>

        <section>
            <h2>Executive Summary</h2>
            <p>
                This report summarizes exported Wazuh security alerts, highlights suspicious activity,
                maps observed behavior to MITRE ATT&CK techniques, and reconstructs an investigation timeline.
            </p>
        </section>

        <section>
            <h2>Threat Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Process</th>
                        <th>Reason</th>
                        <th>MITRE ATT&CK</th>
                    </tr>
                </thead>
                <tbody>
                    {finding_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>MITRE ATT&CK Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Technique</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {mitre_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Investigation Timeline</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Agent</th>
                        <th>Event ID</th>
                        <th>Process</th>
                    </tr>
                </thead>
                <tbody>
                    {timeline_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Indicators of Compromise</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    {ioc_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Recommended Analyst Actions</h2>
            <ul>
                <li>Review suspicious process executions.</li>
                <li>Validate PowerShell activity and command-line arguments.</li>
                <li>Correlate events with endpoint logs and user activity.</li>
                <li>Investigate observed MITRE ATT&CK techniques.</li>
                <li>Check for persistence, lateral movement, and outbound network connections.</li>
            </ul>
        </section>

        <div class="footer">
            Generated by Wazuh Alert Triage
        </div>
    </div>
</body>
</html>
"""

    report_path.write_text(html_report, encoding="utf-8")
    return report_path