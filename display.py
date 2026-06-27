from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]WAZUH ALERT TRIAGE[/bold cyan]\nSecurity alert summary tool",
            border_style="cyan",
        )
    )


def print_severity(severities):
    table = Table(title="Severity Breakdown")
    table.add_column("Rule Level", style="cyan")
    table.add_column("Count", style="green")

    for level, count in severities.items():
        table.add_row(str(level), str(count))

    console.print(table)


def print_agents(agents):
    table = Table(title="Top Agents")
    table.add_column("Agent", style="cyan")
    table.add_column("Count", style="green")

    for agent, count in agents.items():
        table.add_row(str(agent), str(count))

    console.print(table)


def print_findings(findings):
    table = Table(title="Threat Findings")
    table.add_column("Process", style="red")
    table.add_column("Reason", style="yellow")
    table.add_column("MITRE", style="cyan")

    if findings:
        for finding in findings:
            table.add_row(
                finding["process"],
                finding["reason"],
                finding["mitre"],
            )
    else:
        table.add_row("None", "No suspicious activity", "-")

    console.print(table)


def print_timeline(timeline):
    table = Table(title="Investigation Timeline")
    table.add_column("Time", style="cyan")
    table.add_column("Agent", style="green")
    table.add_column("Event", style="yellow")
    table.add_column("Process", style="red")

    for event in timeline:
        table.add_row(
            event["time"],
            event["agent"],
            str(event["event"]),
            event["process"],
        )

    console.print(table)


def print_iocs(iocs):
    table = Table(title="Indicators of Compromise")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="yellow")

    has_iocs = False

    for ioc_type, values in iocs.items():
        if values:
            has_iocs = True
            for value in values:
                table.add_row(ioc_type, str(value))

    if not has_iocs:
        table.add_row("None", "No IOCs extracted")

    console.print(table)