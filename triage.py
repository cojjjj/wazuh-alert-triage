import json
import sys
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def load_alerts(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict) and "alerts" in data:
        return data["alerts"]

    if isinstance(data, dict):
        return [data]

    return []

def get_field(alert, path, default="unknown"):
    current = alert
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, default)
        else:
            return default
    return current if current is not None else default

def main():
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python triage.py <alerts.json>")
        sys.exit(1)

    alerts = load_alerts(sys.argv[1])

    agents = Counter()
    rule_ids = Counter()
    severities = Counter()
    event_ids = Counter()

    for alert in alerts:
        agents[get_field(alert, "agent.name")] += 1
        rule_ids[get_field(alert, "rule.id")] += 1
        severities[get_field(alert, "rule.level")] += 1
        event_ids[get_field(alert, "data.win.system.eventID")] += 1

    console.print(Panel.fit(
        "[bold cyan]WAZUH ALERT TRIAGE[/bold cyan]\nSecurity alert summary tool",
        border_style="cyan"
    ))

    console.print(f"\n[bold]Total Alerts Loaded:[/bold] {len(alerts)}\n")

    severity_table = Table(title="Severity Breakdown")
    severity_table.add_column("Rule Level", style="cyan")
    severity_table.add_column("Count", style="green")

    for level, count in severities.most_common():
        severity_table.add_row(str(level), str(count))

    console.print(severity_table)

    agent_table = Table(title="Top Agents")
    agent_table.add_column("Agent", style="cyan")
    agent_table.add_column("Count", style="green")

    for agent, count in agents.most_common(10):
        agent_table.add_row(str(agent), str(count))

    console.print(agent_table)

    rule_table = Table(title="Top Rule IDs")
    rule_table.add_column("Rule ID", style="cyan")
    rule_table.add_column("Count", style="green")

    for rule_id, count in rule_ids.most_common(10):
        rule_table.add_row(str(rule_id), str(count))

    console.print(rule_table)

    event_table = Table(title="Top Windows / Sysmon Event IDs")
    event_table.add_column("Event ID", style="cyan")
    event_table.add_column("Count", style="green")

    for event_id, count in event_ids.most_common(10):
        event_table.add_row(str(event_id), str(count))

    console.print(event_table)

if __name__ == "__main__":
    main()
