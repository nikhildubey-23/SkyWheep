import requests
import re
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

def crawler(target, depth, visited, threads, data_type="email"):
    print(f"[*] Crawling {target} for {data_type}s...")
    queue = [target]
    visited.add(target)

    # Create a PrettyTable instance
    table = PrettyTable()
    if data_type == "email":
        table.field_names = ["Found Emails", "Source URL"]
    elif data_type == "title":
        table.field_names = ["Found Titles", "Source URL"]
    elif data_type == "phone":
        table.field_names = ["Found Phone Numbers", "Source URL"]

    while queue and depth > 0:
        url = queue.pop(0)
        print(f"    [*] Crawling {url}")

        try:
            response = send_request(url)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")

                if data_type == "email":
                    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", response.text)
                    for email in emails:
                        table.add_row([email, url])  # Add the source URL
                        print(f"        [+] Found {data_type}: {email} from {url}")

                elif data_type == "title":
                    title = soup.title.string if soup.title else "No title found"
                    table.add_row([title, url])  # Add the source URL
                    print(f"        [+] Found {data_type}: {title} from {url}")

                elif data_type == "phone":
                    phones = re.findall(r"\+?\d[\d -]{8,}\d", response.text)  # Basic phone number regex
                    for phone in phones:
                        table.add_row([phone, url])  # Add the source URL
                        print(f"        [+] Found {data_type}: {phone} from {url}")

                # Find all links on the page to continue crawling
                links = soup.find_all("a", href=True)
                for link in links:
                    full_url = link['href']
                    if full_url.startswith('/'):
                        full_url = f"{url}{full_url}"  # Handle relative URLs
                    if full_url not in visited and len(visited) < threads:
                        visited.add(full_url)
                        queue.append(full_url)

            time.sleep(5)
        except Exception as e:
            print(f"    [!] Error crawling {url}: {e}")

        if len(queue) < threads:
            time.sleep(4)

        depth -= 1  # Decrement depth after processing

    print(f"[*] Crawling completed.")
    print(table)

# target_url = input("Enter the target URL to crawl: ")
# crawl_depth = int(input("Enter the crawl depth: "))
# max_threads = int(input("Enter the maximum number of threads: "))
# data_type = input("Enter the data type to crawl (email/title/phone): ").strip().lower()