import re
import json
import sys
import ipaddress
import requests


def is_public_ip(ip):
    """Return True only when the supplied address is a valid public IP."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def enrich_ip(ip):
    """Query ip-api.com and return selected enrichment information."""
    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,isp,hosting,proxy,mobile"
        )

        response = requests.get(url, timeout=5)
        response.raise_for_status()

        data = response.json()

        if data.get("status") == "fail":
            return {
                "error": data.get("message", "IP enrichment failed")
            }

        return {
            "country": data.get("country"),
            "isp": data.get("isp"),
            "hosting": data.get("hosting"),
            "proxy": data.get("proxy"),
            "mobile": data.get("mobile")
        }

    except requests.exceptions.Timeout:
        return {
            "error": "Request timed out"
        }

    except requests.exceptions.RequestException as error:
        return {
            "error": f"HTTP request failed: {error}"
        }

    except (json.JSONDecodeError, ValueError):
        return {
            "error": "The API returned an invalid JSON response"
        }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 log_enricher.py <logfile>")
        sys.exit(1)

    logfile = sys.argv[1]

    # This regex finds four groups of one to three digits separated by dots.
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # A set automatically removes duplicate public IP addresses.
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

    results = {}

    # Sorting provides consistent JSON output each time the script is run.
    for ip in sorted(unique_ips):
        results[ip] = enrich_ip(ip)

    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
