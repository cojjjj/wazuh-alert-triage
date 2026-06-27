import requests
from requests.auth import HTTPBasicAuth


def get_wazuh_token(manager_url, username, password, verify_ssl=False):
    url = f"{manager_url}/security/user/authenticate?raw=true"

    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        verify=verify_ssl
    )

    response.raise_for_status()
    return response.text.strip()


def get_manager_info(manager_url, token, verify_ssl=False):
    url = f"{manager_url}/manager/info"

    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(
        url,
        headers=headers,
        verify=verify_ssl
    )

    response.raise_for_status()
    return response.json()