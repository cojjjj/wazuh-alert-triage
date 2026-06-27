from collections import Counter

from alert_parser import get_field


def text_blob(alert):
    parts = [
        get_field(alert, "rule.id", ""),
        get_field(alert, "rule.description", ""),
        get_field(alert, "rule.groups", ""),
        get_field(alert, "decoder.name", ""),
        get_field(alert, "predecoder.program_name", ""),
        get_field(alert, "program_name", ""),
        get_field(alert, "full_log", ""),
        get_field(alert, "data.command", ""),
        get_field(alert, "data.srcip", ""),
    ]

    return " ".join(str(part) for part in parts).lower()


def detect_suspicious_activity(alerts):
    findings = []
    mitre_hits = Counter()
    risk_score = 0

    for alert in alerts:
        blob = text_blob(alert)

        process = (
            get_field(alert, "data.win.eventdata.image", "")
            or get_field(alert, "predecoder.program_name", "")
            or get_field(alert, "decoder.name", "")
            or "unknown"
        )

        rule_id = str(get_field(alert, "rule.id", "unknown"))
        level = int(get_field(alert, "rule.level", 0) or 0)

        if level >= 10:
            risk_score += 20
        elif level >= 7:
            risk_score += 12
        elif level >= 5:
            risk_score += 6

        if "sudo" in blob:
            findings.append({
                "process": str(process),
                "reason": f"Sudo activity detected, rule {rule_id}",
                "mitre": "T1548 - Abuse Elevation Control Mechanism",
            })
            mitre_hits["T1548 - Abuse Elevation Control Mechanism"] += 1
            risk_score += 8

        if "authentication failed" in blob or "failed password" in blob:
            findings.append({
                "process": str(process),
                "reason": f"Authentication failure detected, rule {rule_id}",
                "mitre": "T1110 - Brute Force",
            })
            mitre_hits["T1110 - Brute Force"] += 1
            risk_score += 10

        if "sshd" in blob and ("accepted password" in blob or "session opened" in blob):
            findings.append({
                "process": str(process),
                "reason": f"SSH login/session activity detected, rule {rule_id}",
                "mitre": "T1021.004 - SSH",
            })
            mitre_hits["T1021.004 - SSH"] += 1
            risk_score += 5

        if "usb" in blob:
            findings.append({
                "process": str(process),
                "reason": f"USB activity detected, rule {rule_id}",
                "mitre": "T1200 - Hardware Additions",
            })
            mitre_hits["T1200 - Hardware Additions"] += 1
            risk_score += 7

        if "powershell" in blob:
            findings.append({
                "process": "powershell.exe",
                "reason": "PowerShell execution detected",
                "mitre": "T1059.001 - PowerShell",
            })
            mitre_hits["T1059.001 - PowerShell"] += 1
            risk_score += 15

        if "encodedcommand" in blob or "-enc" in blob:
            findings.append({
                "process": "powershell.exe",
                "reason": "Encoded PowerShell command detected",
                "mitre": "T1059.001 - PowerShell",
            })
            mitre_hits["T1059.001 - PowerShell"] += 1
            risk_score += 20

    risk_score = min(risk_score, 100)

    return findings, risk_score, mitre_hits