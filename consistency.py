# consistency.py

import requests
from bs4 import BeautifulSoup
import re
import numpy as np
import itertools

# Include your existing functions here or import them if they are in another module

def fetch_csp(url):
    """
    Fetches the Content Security Policy from the headers or meta tag of a URL.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        # Try to get CSP from headers
        csp_header = response.headers.get('Content-Security-Policy', '')
        csp_report_only_header = response.headers.get('Content-Security-Policy-Report-Only', '')

        if csp_header:
            return csp_header.strip()
        else:
            # Check for CSP in meta tags
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_csp = soup.find('meta', {'http-equiv': re.compile('Content-Security-Policy', re.I)})
            if meta_csp and 'content' in meta_csp.attrs:
                return meta_csp['content'].strip()
            elif csp_report_only_header:
                return "The CSP is set to report-only and is not enforced, so it will not affect the page's security."
            else:
                return "No CSP found on this URL."

    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return ""

def parse_csp(csp_string):
    """
    Parses a CSP string into a dictionary where each directive is a key with its values as a list.
    """
    csp_dict = {}
    directives = csp_string.split(';')
    for directive in directives:
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.strip().split()
        directive_name = parts[0]
        directive_values = [value.replace("'", "") for value in parts[1:]]  # Remove any single quotes
        csp_dict[directive_name] = directive_values
    return csp_dict

def csp_dict_to_set(csp_dict):
    """
    Converts a CSP dictionary into a set of (directive, value) pairs.
    """
    directive_value_pairs = set()
    for directive, values in csp_dict.items():
        for value in values:
            directive_value_pairs.add((directive, value))
    return directive_value_pairs

def compute_similarity(set_a, set_b):
    """
    Computes the Jaccard similarity between two sets.
    """
    if not set_a and not set_b:
        return 1.0  # Both sets are empty; consider them identical
    intersection = set_a.intersection(set_b)
    union = set_a.union(set_b)
    similarity = len(intersection) / len(union)
    return similarity

def read_urls(file_path):
    """
    Reads URLs from a text file.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        urls = [line.strip() for line in file if line.strip()]
    return urls

def fetch_csp_policies(urls):
    """
    Fetches CSP policies for a list of URLs.
    """
    csp_policies = {}
    for url in urls:
        print(f"Fetching CSP from {url}")
        csp_string = fetch_csp(url)
        csp_policies[url] = csp_string
    return csp_policies

def parse_and_convert_csp_policies(csp_policies):
    """
    Parses CSP policies and converts them to sets of directive-value pairs.
    """
    csp_dicts = {}
    csp_sets = {}
    for url, csp_string in csp_policies.items():
        if csp_string and "No CSP found" not in csp_string and "not enforced" not in csp_string:
            csp_dict = parse_csp(csp_string)
            csp_dicts[url] = csp_dict
            csp_sets[url] = csp_dict_to_set(csp_dict)
        else:
            csp_dicts[url] = {}
            csp_sets[url] = set()
    return csp_dicts, csp_sets

def compute_pairwise_similarities(csp_sets):
    """
    Computes pairwise similarities between CSP policies.
    """
    urls = list(csp_sets.keys())
    similarities = []
    url_pairs = list(itertools.combinations(urls, 2))
    similarity_matrix = {}
    for url1, url2 in url_pairs:
        set1 = csp_sets[url1]
        set2 = csp_sets[url2]
        similarity = compute_similarity(set1, set2)
        similarities.append(similarity)
        similarity_matrix[(url1, url2)] = similarity
        print(f"Similarity between {url1} and {url2}: {similarity:.4f}")
    return similarities, similarity_matrix

def calculate_overall_consistency(similarities):
    """
    Calculates the overall consistency metric.
    """
    if similarities:
        overall_consistency = sum(similarities) / len(similarities)
    else:
        overall_consistency = 1.0  # Only one page or no pairwise comparisons possible
    print(f"\nOverall Consistency Metric: {overall_consistency:.4f}")
    return overall_consistency

def identify_misconfigurations(urls):
    """
    Identifies misconfigurations in the CSP policies of URLs.
    """
    misconfigurations = {}
    for url in urls:
        issues = eval_csp(url)
        misconfigurations[url] = issues
    return misconfigurations

def compare_misconfigurations(misconfigurations):
    """
    Compares the number of misconfigurations between the main page and subpages.
    """
    urls = list(misconfigurations.keys())
    main_page_url = urls[0]
    main_page_issues = misconfigurations.get(main_page_url, [])
    subpages_urls = urls[1:]
    subpages_issues_counts = [len(misconfigurations.get(url, [])) for url in subpages_urls]
    if subpages_issues_counts:
        average_subpage_misconfigs = sum(subpages_issues_counts) / len(subpages_issues_counts)
    else:
        average_subpage_misconfigs = 0

    print(f"\nMain page ({main_page_url}) misconfigurations: {len(main_page_issues)}")
    print(f"Average subpage misconfigurations: {average_subpage_misconfigs:.2f}")

    if len(main_page_issues) < average_subpage_misconfigs:
        misconfig_comparison = "Subpages have more misconfigurations than the main page."
    elif len(main_page_issues) > average_subpage_misconfigs:
        misconfig_comparison = "Subpages have fewer misconfigurations than the main page."
    else:
        misconfig_comparison = "Subpages have the same number of misconfigurations as the main page."

    print(misconfig_comparison)
    return misconfig_comparison

def analyze_csp_consistency(urls):
    """
    Analyzes the CSP consistency across multiple pages.
    """
    # Fetch CSP Policies
    csp_policies = fetch_csp_policies(urls)

    # Parse and Convert CSP Policies
    csp_dicts, csp_sets = parse_and_convert_csp_policies(csp_policies)

    # Compute Pairwise Similarities
    similarities, similarity_matrix = compute_pairwise_similarities(csp_sets)

    # Calculate Overall Consistency Metric
    overall_consistency = calculate_overall_consistency(similarities)

    # Identify Misconfigurations
    misconfigurations = identify_misconfigurations(urls)

    # Compare Misconfigurations Between Main Page and Subpages
    misconfig_comparison = compare_misconfigurations(misconfigurations)

    # Return results
    results = {
        'overall_consistency': overall_consistency,
        'similarity_matrix': similarity_matrix,
        'misconfigurations': misconfigurations,
        'misconfig_comparison': misconfig_comparison
    }
    return results

def main():
    # Read URLs from test.txt
    urls = read_urls('test.txt')

    # Analyze CSP consistency
    results = analyze_csp_consistency(urls)

    # Print Overall Consistency Metric
    print(f"\nOverall Consistency Metric: {results['overall_consistency']:.4f}")

    # Print Misconfiguration Comparison
    print(results['misconfig_comparison'])

    # Print Detailed Misconfigurations
    print("\nDetailed Misconfiguration Report:")
    for url, issues in results['misconfigurations'].items():
        print(f"\n{url}:")
        if issues:
            for issue in issues:
                print(f"- {issue}")
        else:
            print("No misconfigurations found.")

if __name__ == "__main__":
    main()
