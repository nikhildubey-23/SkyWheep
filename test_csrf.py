import requests
import time
from prettytable import PrettyTable

def send_request(url, method="GET", data=None):
    """Send an HTTP request to the specified URL."""
    try:
        if method.upper() == "POST":
            response = requests.post(url, data=data)
        else:
            response = requests.get(url)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def test_csrf(url, payloads):
    """Test for Cross-Site Request Forgery (CSRF) vulnerabilities."""
    table = PrettyTable(["URL", "CSRF Payload", "Status Code", "CSRF Detected", "Error Message"])
    table.align["CSRF Detected"] = "l"

    test_url = f"{url}/submit"

    for payload in payloads:
        data = {"csrf_token": payload}
        try:
            response = send_request(test_url, method="POST", data=data)
            if response:
                status_code = response.status_code
                csrf_detected = "No"
                error_message = "N/A"

                if payload in response.text:
                    csrf_detected = "Yes"
                    table.add_row([test_url, payload, status_code, csrf_detected, error_message])
                    print(f"       [+] CSRF detected: {test_url}")
                elif status_code == 401 or status_code == 403:
                    table.add_row([test_url, payload, status_code, "Unauthorized", error_message])
                    print(f"       [!] Unauthorized access: {test_url}")
                elif status_code == 404:
                    table.add_row([test_url, payload, status_code, "Not Found", error_message])
                    print(f"       [!] CSRF payload not found: {test_url}")
                else:
                    table.add_row([test_url, payload, status_code, csrf_detected, error_message])
            else:
                table.add_row([test_url, payload, "No Response", csrf_detected, error_message])
        except requests.exceptions.RequestException as e:
            table.add_row([test_url, payload, "Error", "N/A", str(e)])
            print(f"       [!] Error sending request to {test_url}: {e}")
        time.sleep(0.1)

    print(table)

    # Perform additional checks for CSRF
    print("\nAdditional Checks:")
    additional_table = PrettyTable(["URL", "Check Type", "Result"])
    additional_table.align["Check Type"] = "l"

    try:
        response = send_request(test_url, method="POST", data=data)
        if response:
            # Check for CSRF token validation
            if "csrf token validation" in response.text.lower():
                additional_table.add_row([test_url, "CSRF Token Validation", "Detected"])
                print(f"       [!] CSRF token validation detected: {test_url}")
            
            # Check for same-origin policy
            if "same-origin policy" in response.text.lower():
                additional_table.add_row([test_url, "Same-Origin Policy", "Detected"])
                print(f"       [!] Same-origin policy detected: {test_url}")
            
            # Check for cross-site scripting
            if "cross-site scripting" in response.text.lower():
                additional_table.add_row([test_url, "Cross-Site Scripting", "Detected"])
                print(f"       [!] Cross-site scripting detected: {test_url}")
    except requests.exceptions.RequestException as e:
        print(f"       [!] Error sending request to {test_url}: {e}")
    time.sleep(0.1)

    print(additional_table)

payloads = [
    "<img src='x' onerror='alert(\"CSRF\")'>",
    "<script>alert('CSRF')</script>",
    "<iframe src='x' onload='alert(\"CSRF\")'></iframe>",
]

if __name__ == "__main__":
    url = input("Enter the URL to test: ")
    test_csrf(url, payloads)