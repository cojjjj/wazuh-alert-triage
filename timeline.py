from alert_parser import get_field


def first_value(alert, fields, default="unknown"):
    for field in fields:
        value = get_field(alert, field, None)

        if value not in (None, "", [], {}):
            return value

    return default


def get_process_name(alert):
    process = first_value(
        alert,
        [
            "data.win.eventdata.image",
            "data.win.eventdata.processName",
            "data.win.eventdata.originalFileName",
            "data.process.name",
            "process.name",
            "program_name",
            "predecoder.program_name",
            "decoder.name",
        ],
        default="unknown",
    )

    process = str(process)

    if "\\" in process:
        process = process.split("\\")[-1]

    if "/" in process:
        process = process.split("/")[-1]

    return process


def get_event_description(alert):
    return first_value(
        alert,
        [
            "rule.description",
            "description",
            "full_log",
            "data.title",
            "data.win.system.message",
        ],
        default="No description available",
    )


def build_timeline(alerts, limit=50):
    timeline = []

    for alert in alerts:
        timestamp = first_value(
            alert,
            [
                "@timestamp",
                "timestamp",
                "data.timestamp",
            ],
        )

        agent = first_value(
            alert,
            [
                "agent.name",
                "agent.id",
                "manager.name",
                "host.name",
            ],
        )

        event_id = first_value(
            alert,
            [
                "data.win.system.eventID",
                "data.win.system.eventId",
                "data.event_id",
                "rule.id",
                "id",
            ],
        )

        process = get_process_name(alert)
        description = str(get_event_description(alert))

        timeline.append(
            {
                "time": str(timestamp),
                "agent": str(agent),
                "event": str(event_id),
                "process": str(process),
                "description": description[:120],
            }
        )

    timeline.sort(key=lambda item: item["time"])

    return timeline[-limit:]