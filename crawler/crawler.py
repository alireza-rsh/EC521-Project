import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import os
import threading
import time
from urllib.robotparser import RobotFileParser

# Function to read domain names from a text file
def read_domains_from_file(filename):
    domains = []
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            domain = line.strip()
            if domain:  # Skip empty lines
                domains.append(domain)
    return domains

# Set up headers to mimic a regular browser and identify your crawler
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/92.0.4515.159 Safari/537.36'
}

# Lock for thread-safe file writing
file_lock = threading.Lock()

def get_base_domain(netloc):
    parts = netloc.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    else:
        return netloc

def is_allowed_by_robots(domain, url):
    return True
    rp = RobotFileParser()
    robots_url = f"https://{domain}/robots.txt"
    rp.set_url(robots_url)
    try:
        rp.read()
        return rp.can_fetch(headers['User-Agent'], url)
    except:
        # If robots.txt cannot be read, allow crawling
        return True

def find_pages(domain):
    print(f"Processing {domain}")
    urls = []
    main_url_https = f"https://{domain}"
    main_url_http = f"http://{domain}"

    # Try HTTPS first, then HTTP
    try:
        response = requests.head(main_url_https, headers=headers, timeout=5)
        if response.status_code == 200:
            main_url = main_url_https
        else:
            raise Exception
    except:
        main_url = main_url_http

    urls.append(main_url)
    urls_to_visit = [main_url]
    visited_urls = set()

    # Extract base domain (e.g., example.com)
    domain_base = get_base_domain(domain)

    try:
        while len(urls) < 10 and urls_to_visit:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
            visited_urls.add(current_url)

            try:
                response = requests.get(current_url, headers=headers, timeout=10, allow_redirects=True)
                if response.status_code != 200:
                    continue  # Skip URLs that are not accessible

                # Update current domain in case of redirects
                current_domain = urlparse(response.url).netloc
                current_domain_base = get_base_domain(current_domain)

                if current_domain_base != domain_base:
                    # Skip if redirected to a different base domain
                    continue

                soup = BeautifulSoup(response.content, 'html.parser')

                # Find all links on the page
                for link_tag in soup.find_all('a', href=True):
                    href = link_tag['href']
                    parsed_href = urlparse(href)

                    # Skip mailto and javascript links
                    if parsed_href.scheme in ['mailto', 'javascript']:
                        continue

                    # Resolve relative URLs
                    if not parsed_href.netloc:
                        href = urljoin(current_url, href)
                        parsed_href = urlparse(href)

                    link_domain_base = get_base_domain(parsed_href.netloc)

                    # Check if the link is under the same base domain
                    if link_domain_base == domain_base:
                        href = parsed_href.scheme + '://' + parsed_href.netloc + parsed_href.path
                        if href not in urls and len(urls) < 10:
                            # Check if the URL is accessible
                            try:
                                link_response = requests.head(href, headers=headers, timeout=5)
                                if link_response.status_code == 200:
                                    if is_allowed_by_robots(domain, href):
                                        urls.append(href)
                                        urls_to_visit.append(href)
                                    else:
                                        print(f"Skipping {href} due to robots.txt restrictions.")
                                else:
                                    continue
                            except requests.RequestException:
                                continue  # Skip URLs that cause exceptions
                    else:
                        # Ignore URLs from different domains
                        continue
            except requests.RequestException:
                continue  # Skip URLs that cause exceptions

            # Be polite and wait between requests
            time.sleep(1)
    except Exception as e:
        print(f"Error processing {domain}: {e}")

    # Write the URLs to a text file
    filename = f"{domain.replace('.', '_')}.txt"
    with file_lock:
        with open(filename, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(url + '\n')
    print(f"Finished processing {domain}, found {len(urls)} URLs.")

def main():
    # Read domains from 'domains.txt' file
    domains_file = '100MostVisitedSites.txt'
    if not os.path.exists(domains_file):
        print(f"The file '{domains_file}' does not exist.")
        return

    domains = read_domains_from_file(domains_file)
    if not domains:
        print("No domains found in the file.")
        return

    threads = []
    for domain in domains:
        t = threading.Thread(target=find_pages, args=(domain,))
        t.start()
        threads.append(t)
        # Optional: Limit the number of concurrent threads
        if len(threads) >= 5:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads to finish
    for t in threads:
        t.join()

    print("All domains have been processed.")

if __name__ == "__main__":
    main()
