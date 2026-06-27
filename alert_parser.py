import json

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

def extract_process_name(path):
    if not path or path == "unknown":
        return "unknown"

    path = str(path).replace("/", "\\")
    return path.split("\\")[-1].lower()