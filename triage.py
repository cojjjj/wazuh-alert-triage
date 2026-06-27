import json
import sys
from collections import Counter
from rich.console import Console
from rich.table import Table

console = Console()

def load_alerts(path):
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict) and "alerts" in data:
        return data["alerts"]

    return [data]

def main():
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python triage.py <alerts.json>")
        sys.exit(1)

    alerts = load_alerts(sys.argv[1])

    agents = Counter()
    rule_ids = Counter()
    severities = Counter()

    for alert in alerts:
        agent = alert.get("agent", {}).get("name", "unknown")
        rule = alert.get("rule", {})
        rule_id = rule.get("id", "unknown")
        level = rule.get("level", "unknown")

        agents[agent] += 1
        rule_ids[rule_id] += 1
        severities[level] += 1

    console.print("\n[bold cyan]Wazuh Alert Triage Report[/bold cyan]\n")
    console.print(f"[bold]Total Alerts:[/bold] {len(alerts)}")

    table = Table(title="Top Agents")
    table.add_column("Agent")
    table.add_column("Count")

    for agent, count in agents.most_common(5):
        table.add_row(str(agent), str(count))

    console.print(table)

    table = Table(title="Top Rule IDs")
    table.add_column("Rule ID")
    table.add_column("Count")

    for rule_id, count in rule_ids.most_common(10):
        table.add_row(str(rule_id), str(count))

    console.print(table)

    table = Table(title="Severity Counts")
    table.add_column("Rule Level")
    table.add_column("Count")

    for level, count in severities.most_common():
        table.add_row(str(level), str(count))

    console.print(table)

if __name__ == "__main__":
    main()
