import requests
import time
import csv
from prettytable import PrettyTable
from threading import Lock
import subprocess

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

def test_broken_auth(url, credentials):
    """Test for broken authentication using the provided credentials."""
    table = PrettyTable(["Username", "Password", "Status", "Response"])
    table.align["Response"] = "l"

    for cred in credentials:
        data = {"username": cred[0], "password": cred[1]}
        response = send_request(url, data=data, allow_redirects=False)
        
        if response:
            response_text = response.text[:100]
            if "Login failed" not in response_text and "Welcome" in response_text:
                table.add_row([cred[0], cred[1], "Successful Login", response_text])
            else:
                table.add_row([cred[0], cred[1], "Failed Login", response_text])
        else:
            table.add_row([cred[0], cred[1], "No Response", ""])
        
        time.sleep(3)

    with lock:
        # Write the results to a CSV file
        with open('broken_auth_results.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(table.field_names)  # Write the header
            writer.writerows(table.rows)         # Write the data rows

        # Print the table to console
        print(table)

    # Perform additional checks for broken authentication
    print("\nAdditional Checks:")
    additional_checks = []
    for cred in credentials:
        data = {"username": cred[0], "password": cred[1]}
        response = send_request(url, data=data, allow_redirects=False)
        
        if response:
            # Check for weak password policies
            if len(cred[1]) < 8:
                additional_checks.append(f"Weak password detected for: {cred[0]}")
            
            # Check for default or common passwords
            common_passwords = ["password123", "qwerty", "admin"]
            if cred[1].lower() in common_passwords:
                additional_checks.append(f"Common password detected for: {cred[0]}")
            
            # Check for account lockout policy
            if "Account locked" in response.text:
                additional_checks.append(f"Account lockout policy detected for: {cred[0]}")
            
            # Check for rate limiting
            if "Rate limit exceeded" in response.text:
                additional_checks.append(f"Rate limiting detected for: {cred[0]}")
        
        time.sleep(3)

    with lock:
        # Write the additional checks to a CSV file
        with open('broken_auth_additional_checks.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Additional Checks"])  # Write the header
            for check in additional_checks:
                writer.writerow([check])             # Write the data rows

        # Print the additional checks to console
        for check in additional_checks:
            print(f"    [!] {check}")

def run_hydra(url, user_list, password_list):
    """Run Hydra for brute-force login attempts."""
    print("\nRunning Hydra for brute-force login attempts...")
    command = [
        "hydra", 
        "-L", user_list, 
        "-P", password_list, 
        url, 
        "http-post-form", 
        "username=^USER^&password=^PASS^:Login failed:Invalid login"
    ]
    
    # Execute the Hydra command
    try:
        subprocess.run(command)
    except Exception as e:
        print(f"Error running Hydra: {e}")

target_url = input("Enter the target URL: ")
credentials = [
    ("admin", "password123"),
    ("user", "qwerty"),
    ("test", "test123"),
    ("guest", "guest"),
    ("admin", "admin"),
    ]

    # Perform broken authentication testing
test_broken_auth(target_url, credentials)

    # Optionally run Hydra for brute-force attacks
use_hydra = input("Do you want to run Hydra for brute-force login attempts? (yes/no): ").strip().lower()
if use_hydra == 'yes':
    user_list = input("Enter the path to the user list file: ")
    password_list = input("Enter the path to the password list file: ")
    run_hydra(target_url, user_list, password_list)