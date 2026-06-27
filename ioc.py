import ipaddress
import re
from alert_parser import get_field


IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
HASH_PATTERN = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
WINDOWS_PATH_PATTERN = r"[A-Za-z]:\\[^\s\"']+"
LINUX_PATH_PATTERN = r"(?:/[\w.\-]+)+"

BAD_DOMAIN_SUFFIXES = (
    ".yaml",
    ".yml",
    ".conf",
    ".log",
    ".db",
    ".sh",
    ".txt",
    ".service",
    ".bak",
    ".py",
    ".json",
    ".exe",
    ".dll",
    ".sys",
)

BAD_DOMAIN_VALUES = {
    "network.host",
    "http.port",
}


def is_valid_ip(value):
    try:
        ip = ipaddress.ip_address(value)

        if ip.is_loopback:
            return False

        if ip.is_unspecified:
            return False

        if ip.is_multicast:
            return False

        return True

    except ValueError:
        return False


def is_valid_domain(value):
    value = value.lower().strip()

    if value in BAD_DOMAIN_VALUES:
        return False

    if value.endswith(BAD_DOMAIN_SUFFIXES):
        return False

    if len(value) < 4:
        return False

    if "." not in value:
        return False

    return True


def extract_iocs(alerts):
    iocs = {
        "ips": set(),
        "domains": set(),
        "hashes": set(),
        "file_paths": set(),
    }

    for alert in alerts:
        fields_to_scan = [
            get_field(alert, "data.srcip", ""),
            get_field(alert, "data.dstip", ""),
            get_field(alert, "srcip", ""),
            get_field(alert, "dstip", ""),
            get_field(alert, "full_log", ""),
            get_field(alert, "data.win.eventdata.commandLine", ""),
            get_field(alert, "data.win.eventdata.image", ""),
            get_field(alert, "data.url", ""),
            get_field(alert, "data.hostname", ""),
        ]

        text_blob = " ".join(str(field) for field in fields_to_scan if field)

        for ip in re.findall(IP_PATTERN, text_blob):
            if is_valid_ip(ip):
                iocs["ips"].add(ip)

        for domain in re.findall(DOMAIN_PATTERN, text_blob):
            if is_valid_domain(domain):
                iocs["domains"].add(domain.lower())

        for hash_value in re.findall(HASH_PATTERN, text_blob):
            iocs["hashes"].add(hash_value.lower())

        for path in re.findall(WINDOWS_PATH_PATTERN, text_blob):
            iocs["file_paths"].add(path)

        for path in re.findall(LINUX_PATH_PATTERN, text_blob):
            if len(path) > 4:
                iocs["file_paths"].add(path)

    return {
        key: sorted(value)
        for key, value in iocs.items()
    }