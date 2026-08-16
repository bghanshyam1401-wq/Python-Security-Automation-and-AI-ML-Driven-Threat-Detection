import os
import re
import sys
import json
import ipaddress
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv


# Load environment variables from the local .env file.
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")


def is_public_ip(ip):
    """Return True only if the supplied value is a valid public IP."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def extract_public_ips(logfile):
    """Extract and deduplicate public IPv4 addresses from a log file."""

    # Match four groups of one to three digits separated by dots.
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # A set removes duplicate addresses automatically.
    unique_ips = set()

    try:
        with open(logfile, "r", encoding="utf-8") as log_file:
            for line in log_file:
                matches = re.findall(ip_pattern, line)

                for ip in matches:
                    if is_public_ip(ip):
                        unique_ips.add(ip)

    except FileNotFoundError:
        print(f"Error: Log file not found: {logfile}")
        sys.exit(1)

    except OSError as error:
        print(f"Error reading log file: {error}")
        sys.exit(1)

    return sorted(unique_ips)


def check_ip(ip):
    """Query VirusTotal for analysis information about one IP."""

    url = (
        "https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip}"
    )

    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 401:
            return {
                "error": "Invalid or missing VirusTotal API key"
            }

        if response.status_code == 404:
            return {
                "error": "IP address was not found in VirusTotal"
            }

        if response.status_code == 429:
            return {
                "error": "VirusTotal API rate limit exceeded"
            }

        response.raise_for_status()

        try:
            data = response.json()
        except (requests.exceptions.JSONDecodeError, ValueError):
            return {
                "error": "VirusTotal returned invalid JSON"
            }

        attributes = data.get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        last_analysis_timestamp = attributes.get(
            "last_analysis_date"
        )

        if last_analysis_timestamp:
            last_analysis_date = datetime.fromtimestamp(
                last_analysis_timestamp,
                tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            last_analysis_date = "Not available"

        return {
            "malicious": stats.get("malicious", 0),
            "harmless": stats.get("harmless", 0),
            "last_analysis_date": last_analysis_date
        }

    except requests.exceptions.Timeout:
        return {
            "error": "VirusTotal request timed out"
        }

    except requests.exceptions.ConnectionError:
        return {
            "error": "Unable to connect to VirusTotal"
        }

    except requests.exceptions.HTTPError as error:
        return {
            "error": f"VirusTotal HTTP error: {error}"
        }

    except requests.exceptions.RequestException as error:
        return {
            "error": f"VirusTotal request failed: {error}"
        }


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python3 virustotal_check.py "
            "<logfile>"
        )
        sys.exit(1)

    if not API_KEY:
        print(
            "Error: VT_API_KEY was not found. "
            "Add it to the local .env file."
        )
        sys.exit(1)

    logfile = sys.argv[1]

    public_ips = extract_public_ips(logfile)

    if not public_ips:
        print("No public IPv4 addresses found in the log file.")
        return

    print(
        f"Checking {len(public_ips)} unique public "
        "IP addresses with VirusTotal...\n"
    )

    results = {}

    for ip in public_ips:
        results[ip] = check_ip(ip)
    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()

