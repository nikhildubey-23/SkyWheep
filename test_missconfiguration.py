import requests
import time
from prettytable import PrettyTable

def send_request(url):
    """Send an HTTP request to the specified URL."""
    try:
        response = requests.get(url)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def test_misconfig(url, misconfig_types):
    """Test for specific security misconfigurations."""
    table = PrettyTable(["URL", "Misconfiguration Type", "Status Code", "Misconfiguration Detected", "Error Message"])
    table.align["Misconfiguration Detected"] = "l"

    response = send_request(url)
    if response:
        status_code = response.status_code
        error_message = "N/A"

        for misconfig_type in misconfig_types:
            misconfig_detected = "No"

            # Check for specific misconfiguration types
            if misconfig_type == "Server" and "server" in response.headers:
                misconfig_detected = "Yes"
                table.add_row([url, misconfig_type, status_code, misconfig_detected, error_message])
                print(f"    [+] Security Misconfiguration detected: {url} ({misconfig_type})")
            elif misconfig_type == "X-Powered-By" and "x-powered-by" in response.headers:
                misconfig_detected = "Yes"
                table.add_row([url, misconfig_type, status_code, misconfig_detected, error_message])
                print(f"    [+] Security Misconfiguration detected: {url} ({misconfig_type})")
            elif misconfig_type == "X-AspNet-Version" and "x-asp-net-version" in response.headers:
                misconfig_detected = "Yes"
                table.add_row([url, misconfig_type, status_code, misconfig_detected, error_message])
                print(f"    [+] Security Misconfiguration detected: {url} ({misconfig_type})")
            else:
                table.add_row([url, misconfig_type, status_code, misconfig_detected, error_message])
    else:
        table.add_row([url, misconfig_types, "No Response", "No", error_message])
    
    print(table)

    # Perform additional checks for Security Misconfiguration
    print("\nAdditional Checks:")
    additional_table = PrettyTable(["URL", "Check Type", "Result"])
    additional_table.align["Check Type"] = "l"

    # Check for outdated software
    if response:
        if "x-powered-by" in response.headers and "asp.net" in response.headers["x-powered-by"].lower():
            additional_table.add_row([url, "Outdated Software", "Detected"])
            print(f"    [!] Outdated software detected: {url}")
        elif "server" in response.headers and "apache" in response.headers["server"].lower():
            additional_table.add_row([url, "Outdated Software", "Detected"])
            print(f"    [!] Outdated software detected: {url}")

    # Check for missing security headers
    if response:
        if "content-security-policy" not in response.headers:
            additional_table.add_row([url, "Missing Security Header", "Detected"])
            print(f"    [!] Missing security header detected: {url}")
        if "x-frame-options" not in response.headers:
            additional_table.add_row([url, "Missing Security Header", "Detected"])
            print(f"    [!] Missing security header detected: {url}")

    # Check for insecure protocols
    if response:
        if "https" not in response.url:
            additional_table.add_row([url, "Insecure Protocol", "Detected"])
            print(f"    [!] Insecure protocol detected: {url}")

    print(additional_table)

misconfig_types = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
    ]

if __name__ == "__main__":
    url = input("Enter the URL to test: ")
    test_misconfig(url, misconfig_types)