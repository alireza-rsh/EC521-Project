import time
from urllib.parse import urlparse
from googlesearch import search
import os

# Input file with domains
domains_file = "domain10.txt"
output_dir = "google_results"

# Create the output directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Read domains and process each
with open(domains_file, "r") as file:
    domains = file.readlines()

for domain in domains:
    domain = domain.strip()
    if domain:  # Skip empty lines
        output_file = os.path.join(output_dir, f"{domain}.txt")
        query = f"site:www.{domain}"
        final_urls = []

        print(f"Searching for: {query}")
        try:
            # First attempt: site:www.domain
            urls = list(search(query, num_results=100))
            # If no results, try site:domain
            if len(urls)<10:
                #print(f"No results for {query}. Retrying with site:{domain}...")
                query = f"site:{domain}"
                urls = search(query, num_results=100)

            # Save results to the file
            with open(output_file, "w") as f:
                for url in urls:
                    f.write(url + "\n")

            if urls:
                print(f"Results saved to: {output_file}")
            else:
                print(f"No valid URLs found for {domain}. File will be empty.")
        except Exception as e:
            print(f"An error occurred for {domain}: {e}")
        
        # Add a delay to avoid rate limiting
        time.sleep(2)
