import time
import hashlib
import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VTError(Exception):
    pass


def get_file_report(api_key: str, file_hash: str):
    """
    Get VirusTotal report by file hash.
    Returns JSON or None if not found.
    """
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/files/{file_hash}"

    response = requests.get(url, headers=headers, timeout=15)

    if response.status_code == 200:
        return response.json()

    if response.status_code == 404:
        return None

    raise VTError(f"VirusTotal error: {response.status_code}")


def upload_file_for_scan(api_key: str, file_path: str):
    """
    Upload file to VirusTotal.
    Returns analysis_id.
    """
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/files"

    with open(file_path, "rb") as f:
        response = requests.post(
            url,
            headers=headers,
            files={"file": f},
            timeout=30,
        )

    if response.status_code not in (200, 201):
        raise VTError("Failed to upload file to VirusTotal")

    return response.json()["data"]["id"]


def wait_for_analysis(api_key: str, analysis_id: str, timeout_seconds: int = 20):
    """
    Poll VirusTotal analysis endpoint.
    """
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/analyses/{analysis_id}"

    start = time.time()

    while time.time() - start < timeout_seconds:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            raise VTError("Failed to fetch analysis status")

        data = response.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            return data

        time.sleep(3)

    return None


def extract_stats_from_file_report(report: dict):
    """
    Extract stats from file hash report.
    """
    stats = report["data"]["attributes"]["last_analysis_stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    file_hash = report["data"]["id"]
    link = f"https://www.virustotal.com/gui/file/{file_hash}"

    return malicious, suspicious, harmless, link


def extract_stats_from_analysis(analysis: dict):
    """
    Extract stats from analysis response.
    """
    stats = analysis["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    return malicious, suspicious