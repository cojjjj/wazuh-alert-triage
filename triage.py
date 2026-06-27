import argparse
from collections import Counter

from alert_parser import load_alerts, get_field
from detector import detect_suspicious_activity
from timeline import build_timeline
from ioc import extract_iocs
from opensearch_api import get_indexer_alerts
from display import (
    banner,
    print_severity,
    print_agents,
    print_findings,
    print_timeline,
    print_iocs,
)
from reports import generate_markdown_report, generate_html_report


def print_summary(total_alerts, risk_score):
    print()
    print(f"Total Alerts Loaded: {total_alerts}")
    print(f"Risk Score: {risk_score}/100")

    if risk_score >= 75:
        print("Risk Level: HIGH")
    elif risk_score >= 40:
        print("Risk Level: MEDIUM")
    elif risk_score > 0:
        print("Risk Level: LOW")
    else:
        print("Risk Level: NONE")

    print()


def analyze_alerts(alerts):
    severities = Counter()
    agents = Counter()

    for alert in alerts:
        severities[get_field(alert, "rule.level")] += 1
        agents[get_field(alert, "agent.name")] += 1

    findings, risk_score, mitre_hits = detect_suspicious_activity(alerts)
    timeline = build_timeline(alerts)
    iocs = extract_iocs(alerts)

    banner()
    print_summary(len(alerts), risk_score)
    print_severity(severities)
    print_agents(agents)
    print_findings(findings)
    print_timeline(timeline)
    print_iocs(iocs)

    markdown_path = generate_markdown_report(
        alerts,
        findings,
        risk_score,
        mitre_hits,
        timeline,
    )

    html_path = generate_html_report(
        alerts,
        findings,
        risk_score,
        mitre_hits,
        timeline,
        iocs,
    )

    print()
    print(f"Markdown report saved to: {markdown_path}")
    print(f"HTML report saved to: {html_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Wazuh Alert Triage Tool"
    )

    parser.add_argument(
        "json",
        nargs="?",
        help="Exported Wazuh alert JSON file"
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help="Pull alerts directly from Wazuh Indexer / OpenSearch"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=250,
        help="Number of alerts to pull in live mode"
    )

    args = parser.parse_args()

    if args.live:
        indexer_url = input(
            "Indexer URL (default: https://127.0.0.1:9200): "
        ).strip()

        if not indexer_url:
            indexer_url = "https://127.0.0.1:9200"

        indexer_username = input("Indexer Username: ").strip()
        indexer_password = input("Indexer Password: ").strip()

        print()
        print("Pulling alerts from Wazuh Indexer...")

        alerts = get_indexer_alerts(
            indexer_url=indexer_url,
            username=indexer_username,
            password=indexer_password,
            limit=args.limit,
            verify_ssl=False,
        )

        analyze_alerts(alerts)

    else:
        if not args.json:
            parser.error("Please provide a JSON file or use --live.")

        alerts = load_alerts(args.json)
        analyze_alerts(alerts)


if __name__ == "__main__":
    main()