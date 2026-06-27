import requests
from requests.auth import HTTPBasicAuth


def get_indexer_alerts(indexer_url, username, password, limit=100, verify_ssl=False):
    url = f"{indexer_url.rstrip('/')}/wazuh-alerts-*/_search"

    payload = {
        "size": limit,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "match_all": {}
        }
    }

    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        json=payload,
        verify=verify_ssl,
    )

    if not response.ok:
        print("OpenSearch error:")
        print(response.status_code)
        print(response.text)
        response.raise_for_status()

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    return [hit.get("_source", {}) for hit in hits]