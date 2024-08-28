import requests
import time
import logging
from bs4 import BeautifulSoup
from prettytable import PrettyTable

# Set up logging
logging.basicConfig(level=logging.INFO)

def send_request(url):
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

def test_csp_bypass(url):
    csp_bypass_payloads = [
        "<script>alert('CSP Bypass')</script>",
        "<script>eval('alert(\"CSP Bypass\")')</script>",
        "<script>new Function('alert(\"CSP Bypass\")')()</script>",
        "<script>setTimeout('alert(\"CSP Bypass\")', 0)</script>",
        "<script>setInterval('alert(\"CSP Bypass\")', 0)</script>",
    ]

    table = PrettyTable()
    table.field_names = ["Test", "Result", "Description", "HTTP Status", "Response Time (s)"]

    for payload in csp_bypass_payloads:
        test_url = f"{url}?param={payload}"
        start_time = time.time()
        response = send_request(test_url)
        response_time = time.time() - start_time

        if response:
            # Log the HTTP status code
            logging.info(f"HTTP Status Code: {response.status_code}")

            # Check for CSP bypass
            if payload in str(BeautifulSoup(response.text, "html.parser")):
                table.add_row(["CSP Bypass", "Vulnerable", "CSP bypass detected", response.status_code, round(response_time, 4)])
            else:
                # Check for Content Security Policy header
                csp_header = response.headers.get("Content-Security-Policy", "")
                if csp_header:
                    table.add_row(["Content Security Policy", "Secure", "CSP header present", response.status_code, round(response_time, 4)])
                else:
                    table.add_row(["Content Security Policy", "Vulnerable", "Missing CSP header", response.status_code, round(response_time, 4)])

            # Check for other security headers
            if "X-Content-Type-Options" not in response.headers:
                table.add_row(["X-Content-Type-Options", "Vulnerable", "Missing X-Content-Type-Options header", response.status_code, round(response_time, 4)])
            else:
                table.add_row(["X-Content-Type-Options", "Secure", "X-Content-Type-Options header present", response.status_code, round(response_time, 4)])

            if "X-XSS-Protection" not in response.headers:
                table.add_row(["X-XSS-Protection", "Vulnerable", "Missing X-XSS-Protection header", response.status_code, round(response_time, 4)])
            else:
                table.add_row(["X-XSS-Protection", "Secure", "X-XSS-Protection header present", response.status_code, round(response_time, 4)])

        else:
            logging.warning(f"Failed to retrieve response from {test_url}")

    print(table)
    time.sleep(0.1)

