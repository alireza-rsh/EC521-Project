import requests
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
from collections import defaultdict, Counter
import re
import os
import numpy as np
import itertools
import matplotlib.pyplot as plt

def fetch_csp(url):
    """
    Fetches the Content Security Policy from the headers or meta tag of a URL.
    If only a report-only CSP is found, returns a message indicating it is not enforced.

    Args:
        url (str): The URL to fetch the CSP from.

    Returns:
        str: The raw CSP string if enforced, or a message if only report-only is found.
    """
    try:
        headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        )
        }
        # Send request to the URL
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # Try to get CSP from headers
        csp_header = response.headers.get('Content-Security-Policy', '')
        csp_report_only_header = response.headers.get('Content-Security-Policy-Report-Only', '')

        # Return the enforced CSP header if present
        if csp_header:
            return csp_header
        # Check for CSP in the meta tag if no enforced header is found
        else:
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_csp = soup.find('meta', {'http-equiv': re.compile('Content-Security-Policy', re.I)})
            if meta_csp and 'content' in meta_csp.attrs:
                return meta_csp['content']
            # If only report-only CSP is found, return a message
            elif csp_report_only_header:
                return "The CSP is set to report-only and is not enforced, so it will not affect the page's security."
        
        # If no CSP is found, return an empty string or a message
        return "No CSP found on this URL."

    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return "Error fetching URL."

def parse_csp(csp_string):
    """
    Parses a CSP string into a dictionary where each directive is a key with its values as a list.

    Args:
        csp_string (str): The CSP string to parse.

    Returns:
        dict: A dictionary with directive names as keys and lists of values as values, without any quotes.
    """
    csp_dict = {}
    # Split each directive by semicolon
    directives = csp_string.split(';')
    for directive in directives:
        directive = directive.strip()
        if not directive:
            continue
        # Split the directive into its name and values
        parts = directive.split()
        directive_name = parts[0]
        directive_values = [value.replace("'", "'") for value in parts[1:]]  # Remove any single quotes

        # Store in dictionary
        csp_dict[directive_name] = directive_values

    return csp_dict

def script_src_check(script_src_values, issues):
    """
    Checks for common misconfigurations in the 'script-src' directive of CSP.
    If 'strict-dynamic' is present, skips other source checks but still checks for 'unsafe-eval'.

    Args:
        script_src_values (list): A list of sources specified in the 'script-src' directive.

    Returns:
        list: A list of strings describing any misconfigurations found.
    """

    # Check for strict-dynamic first; if present, note its presence and skip other source checks
    if "'strict-dynamic'" in script_src_values:
        issues.append("script-src: Contains 'strict-dynamic' - other source expressions are ignored, relying only on trusted dynamic scripts.")
    
    # Check for 'unsafe-eval' regardless of 'strict-dynamic'
    if "'unsafe-eval'" in script_src_values:
        issues.append("script-src: Contains 'unsafe-eval' - allows the use of eval() and similar methods, which can be exploited for XSS.")

    # If strict-dynamic is present, skip checks for wildcard (*), self, and other host sources
    if "'strict-dynamic'" not in script_src_values:
        # Check for wildcard (*)
        if '*' in script_src_values:
            issues.append("script-src: Contains wildcard '*' - allows scripts from any source, reducing security.")
        
        # Check for 'unsafe-inline'
        has_hashes = any(source.startswith("'sha") for source in script_src_values)
        if has_hashes:
            # Check for 'unsafe-hashes'
            if "'unsafe-hashes'" in script_src_values:
                issues.append("script-src: Contains 'unsafe-hashes' - allows the use of hashes for event handlers, which can be unsafe.")
        has_nonce = any(src.startswith("'nonce-") for src in script_src_values)
        if "'unsafe-inline'" in script_src_values:
            if has_hashes or has_nonce:
                issues.append("script-src: unsafe-inline is ignored if a nonce or a hash is present.")
            else:
                issues.append("script-src: Contains 'unsafe-inline' - allows inline scripts, making it vulnerable to XSS attacks.")

        # Check for overly broad HTTPS source (e.g., 'https:' without specifying a domain)
        if any(source == 'https:' for source in script_src_values):
            issues.append("script-src: Contains broad 'https:' source - allows scripts from any HTTPS domain, which may introduce risks.")
        
        # Check if hashes are present and flag if combined with 'unsafe-inline'
        
        
        # Check if self is allowed and flag it (self is generally okay but worth noting)
        if "'self'" in script_src_values:
            issues.append("script-src: Contains 'self' - allows scripts from the same origin, generally safe but can be exploited if there is no restriction for File Uploads.")
        
        # General warning for any host URLs (http:// or https://)
        url_pattern = re.compile(r'^https?://[^\s]+')
        if any(url_pattern.match(source) for source in script_src_values):
            issues.append("script-src: Contains host URLs - ensure that no URLs in the 'script-src' serve JSONP responses or Angular libraries to prevent potential security risks.")
    
    return issues
    
def object_src_check(object_src_values, issues):
    """
    Checks for common misconfigurations in the 'object-src' directive of CSP.

    Args:
        object_src_values (list): A list of sources specified in the 'object-src' directive.
        issues (list): List to append any identified issues.
    """

    # 2. Check for wildcard '*' which allows objects from any source
    if '*' in object_src_values:
        issues.append("object-src: Contains wildcard '*' - allows objects from any source, increasing the risk of XSS.")

    # 3. Check for specific potentially dangerous sources
    dangerous_sources = ['data:', 'blob:']
    for src in object_src_values:
        if src in dangerous_sources:
            issues.append(f"object-src: Contains dangerous source '{src}' - can be exploited to execute malicious objects.")

    # 4. Check for protocol-relative URLs (e.g., //example.com)
    url_pattern = re.compile(r'^https?://[^\s]+')
    if any(url_pattern.match(source) for source in object_src_values):
        issues.append(f"object-src: Contains host URLs - can lead to loading objects over unintended protocols.")

    # 5. Warn if 'self' is allowed, as it permits objects from the same origin
    if "'self'" in object_src_values:
        issues.append("object-src: Contains 'self' - allows objects from the same origin, which can be exploited if there is no restriction for File Uploads.")

def img_src_check(img_src_values, issues):
    """
    Checks for common misconfigurations in the 'img-src' directive of CSP.

    Args:
        img_src_values (list): A list of sources specified in the 'img-src' directive.
        issues (list): List to append any identified issues.
    """

    # 1. Check for wildcard '*' which allows images from any source
    if '*' in img_src_values:
        issues.append("img-src: Contains wildcard '*' - allows images from any source, which can be exploited for data exfiltration.")

    # 2. Check for dangerous schemes
    dangerous_schemes = ['data:', 'blob:']
    for src in img_src_values:
        if src in dangerous_schemes:
            issues.append(f"img-src: Contains dangerous scheme '{src}' - can be exploited to embed arbitrary images and compromise content integrity.")

def media_src_check(media_src_values, issues):
    """
    Checks for common misconfigurations in the 'media-src' directive of CSP.

    Args:
        media_src_values (list): A list of sources specified in the 'media-src' directive.
        issues (list): List to append any identified issues.
    """
    # 1. Check for wildcard '*' which allows media from any source
    if '*' in media_src_values:
        issues.append("media-src: Contains wildcard '*' - allows media from any source, which can be exploited for data exfiltration.")

    # 2. Check for dangerous schemes
    dangerous_schemes = ['data:', 'blob:']
    for src in media_src_values:
        if src in dangerous_schemes:
            issues.append(f"media-src: Contains dangerous scheme '{src}' - can be exploited to embed arbitrary media and compromise content integrity.")

def font_src_check(font_src_values, issues):
    """
    Checks for common misconfigurations in the 'font-src' directive of CSP.

    Args:
        font_src_values (list): A list of sources specified in the 'font-src' directive.
        issues (list): List to append any identified issues.
    """
    # 1. Check for wildcard '*'
    if '*' in font_src_values:
        issues.append("font-src: Contains wildcard '*' - allows fonts from any source, which may pose a risk.")

    # 2. Check for dangerous schemes
    dangerous_schemes = ['data:', 'blob:']
    for src in font_src_values:
        if src in dangerous_schemes:
            issues.append(f"font-src: Contains dangerous scheme '{src}' - can be exploited to load malicious fonts.")

    # 4. Check for 'self' and note that it's generally acceptable
    if "'self'" in font_src_values:
        issues.append("font-src: Contains 'self' - allows fonts from the same origin, generally safe but verify necessity.")

    # 5. Check for external URLs
    url_pattern = re.compile(r'^https?://[^\s]+')
    if any(url_pattern.match(source) for source in font_src_values):
        issues.append(f"font-src: Contains host URLs - ensure that external fonts are from trusted sources.")

def base_uri_check(base_uri_values, issues):
    """
    Checks for common misconfigurations in the 'base-uri' directive of CSP.

    Args:
        base_uri_values (list): A list of sources specified in the 'base-uri' directive.
        issues (list): List to append any identified issues.
    """
    # 1. Check for wildcard '*' which allows any base URI
    if '*' in base_uri_values:
        issues.append("base-uri: Contains wildcard '*' - allows the base URI to be set to any origin, increasing the risk of malicious resource loading.")

def style_src_check(style_src_values, issues):
    """
    Checks for common misconfigurations in the 'style-src' directive of CSP.

    Args:
        style_src_values (list): A list of sources specified in the 'style-src' directive.
        issues (list): List to append any identified issues.
    """
    # Check for 'unsafe-inline'
    has_hashes = any(source.startswith("'sha") for source in style_src_values)
    has_nonce = any(src.startswith("'nonce-") for src in style_src_values)
    if "'unsafe-inline'" in style_src_values:
        if has_hashes or has_nonce:
            issues.append("style-src: 'unsafe-inline' is ignored if a nonce or a hash is present.")
        else:
            issues.append("style-src: Contains 'unsafe-inline' - allows inline styles, making it vulnerable to XSS attacks.")

    # Check for wildcard '*'
    if '*' in style_src_values:
        issues.append("style-src: Contains wildcard '*' - allows styles from any source, reducing security.")

    # Check for dangerous schemes
    dangerous_schemes = ['data:', 'blob:']
    for src in style_src_values:
        if src in dangerous_schemes:
            issues.append(f"style-src: Contains dangerous scheme '{src}' - can be exploited to inject malicious styles.")

    # Check for 'self'
    if "'self'" in style_src_values:
        issues.append("style-src: Contains 'self' - allows styles from the same origin, generally safe but verify necessity.")

    # Check for external URLs
    url_pattern = re.compile(r'^https?://[^\s]+')
    if any(url_pattern.match(source) for source in style_src_values):
        issues.append(f"style-src: Contains host URLs - ensure that external styles are from trusted sources.")

def frame_src_check(frame_src_values, issues):
    """
    Checks for common misconfigurations in the 'frame-src' directive of CSP.

    Args:
        frame_src_values (list): A list of sources specified in the 'frame-src' directive.
        issues (list): List to append any identified issues.
    """
    # 1. Check for wildcard '*'
    if '*' in frame_src_values:
        issues.append("frame-src: Contains wildcard '*' - allows framing content from any source, which can lead to clickjacking or defacement.")

    # 2. Check for 'self'
    if "'self'" in frame_src_values:
        issues.append("frame-src: Contains 'self' - allows framing content from the same origin. Ensure this is necessary and safe.")

    # 3. Check for external URLs
    url_pattern = re.compile(r'^https?://[^\s]+')
    if any(url_pattern.match(source) for source in frame_src_values):
        issues.append(f"frame-src: Contains host URLs - ensure that external framing sources are trusted and necessary.")

def apply_default_src(csp_dict, issues):
    """
    Applies default-src values to missing fetch directives if default-src is defined.

    Args:
        csp_dict (dict): Parsed CSP dictionary.

    Returns:
        dict: Updated CSP dictionary with default-src values applied to missing directives.
    """
    fetch_directives = ['script-src', 'style-src', 'img-src', 'media-src', 'object-src', 'font-src', 'frame-src']
    default_src_values = []
    is_default_src_available = 0
    if 'default-src' in csp_dict:
        default_src_values = csp_dict['default-src']
        is_default_src_available = 1
        
    if not default_src_values:
        issues.append("Missing 'default-src' directive - it's recommended to define a default policy for all sources.")

    # List of fetch directives to check.
    for directive in fetch_directives:
        if directive not in csp_dict:
            if is_default_src_available:
                csp_dict[directive] = default_src_values
                issues.append(f"{directive} is missing. Using default-src values as fallback.")
            else:
                issues.append(f"{directive} is missing.")

    return csp_dict

def eval_csp(csp_string):
    issues = []
    csp_dict = []
    if csp_string != "No CSP found on this URL." and csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security." and csp_string != "Error fetching URL.":
        csp_dict = parse_csp(csp_string)
        csp_dict = apply_default_src(csp_dict, issues)
        if 'script-src' in csp_dict:
            script_src_values = csp_dict['script-src']
            script_src_check(script_src_values, issues)
        if 'object-src' in csp_dict:
            object_src_values = csp_dict['object-src']
            object_src_check(object_src_values, issues)
        if 'img-src' in csp_dict:
            img_src_values = csp_dict['img-src']
            img_src_check(img_src_values, issues)
        if 'media-src' in csp_dict:
            media_src_values = csp_dict['media-src']
            media_src_check(media_src_values, issues)
        if 'base-uri' in csp_dict:
            base_uri_values = csp_dict['base-uri']
            base_uri_check(base_uri_values, issues)
        if 'base-uri' not in csp_dict:
            issues.append("base-uri is missing.")
        if 'style-src' in csp_dict:
            style_src_values = csp_dict['style-src']
            style_src_check(style_src_values, issues)
        if 'font-src' in csp_dict:
            font_src_values = csp_dict['font-src']
            font_src_check(font_src_values, issues)
        if 'frame-src' in csp_dict:
            frame_src_values = csp_dict['frame-src']
            frame_src_check(frame_src_values, issues)
    else:
        issues.append(csp_string)
    return issues

def analyze_csp_prevalence(csp_policies):
    """
    Analyzes the prevalence of CSP implementation among the top 100 websites.

    Takes in a dictionary of csp_policies, checks each for CSP implementation,
    and reports the percentage of sites with enforced CSP, report-only CSP, and no CSP.
    """
    # Initialize counters
    total_sites = len(csp_policies)
    enforced_csp_count = 0
    report_only_csp_count = 0
    no_csp_count = 0
    error_count = 0

    print(f"Total sites to analyze: {total_sites}")

    for domain, csp_string in csp_policies.items():
        if csp_string == "No CSP found on this URL.":
            no_csp_count += 1
        elif csp_string == "The CSP is set to report-only and is not enforced, so it will not affect the page's security.":
            report_only_csp_count += 1
        elif csp_string == "Error fetching URL.":
            error_count += 1
        else:
            enforced_csp_count += 1

    # Calculate percentages
    total_valid_sites = total_sites - error_count
    if total_valid_sites > 0:
        enforced_csp_percentage = (enforced_csp_count / total_valid_sites) * 100
        report_only_csp_percentage = (report_only_csp_count / total_valid_sites) * 100
        no_csp_percentage = (no_csp_count / total_valid_sites) * 100
    else:
        enforced_csp_percentage = report_only_csp_percentage = no_csp_percentage = 0

    # Report the results
    print("\nCSP Implementation Analysis:")
    print(f"Total sites analyzed (excluding errors): {total_valid_sites}")
    print(f"Sites with enforced CSP: {enforced_csp_count} ({enforced_csp_percentage:.2f}%)")
    print(f"Sites with report-only CSP: {report_only_csp_count} ({report_only_csp_percentage:.2f}%)")
    print(f"Sites with no CSP: {no_csp_count} ({no_csp_percentage:.2f}%)")
    if error_count > 0:
        print(f"Sites with errors during fetching: {error_count}")
    categories = ["Enforced CSP", "Report-Only CSP", "No CSP"]
    counts = [enforced_csp_count, report_only_csp_count, no_csp_count]
    colors = ["#1f77b4", "#ff7f0e", "#d62728"]  # Custom colors

    # Create the bar chart
    plt.figure(figsize=(10, 6))
    bars = plt.bar(categories, counts, color=colors, edgecolor="black")

    # Add labels to each bar
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() - 5,
                str(bar.get_height()), ha="center", va="bottom", fontsize=12, color="white")

    # Add titles and labels
    plt.title("CSP Implementation Analysis (Counts)", fontsize=16, fontweight="bold")
    plt.xlabel("CSP Implementation", fontsize=12)
    plt.ylabel("Number of Sites", fontsize=12)

    # Show grid for better readability
    plt.grid(axis="y", linestyle="--", alpha=0.7)

    plt.tight_layout()
    plot = os.path.join(".", "analyze_csp_prevalence.png")
    plt.savefig(plot)
    plt.close()

def collect_csp_policies(domains):
    csp_policies = {}
    for domain in domains:
        url_https = f"https://{domain}"
        url_http = f"http://{domain}"
        url = url_https  # Default to HTTPS

        # Try accessing the site via HTTPS; fallback to HTTP if needed
        try:
            response = requests.head(url, timeout=5)
            if response.status_code >= 400:
                url = url_http
        except requests.RequestException:
            url = url_http

        print(f"Fetching CSP from {url}")

        csp_string = fetch_csp(url)

        csp_policies[domain] = csp_string

    return csp_policies

def eval_csp_v2(csp_policies):
    misconfigurations = defaultdict(int)
    directives_misconfigured = defaultdict(int)
    domain_issues = {}
    for domain, csp_string in csp_policies.items():
        issues = []
        if csp_string != "No CSP found on this URL." and csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security." and csp_string != "Error fetching URL.":
            csp_dict = parse_csp(csp_string)
            csp_dict = apply_default_src(csp_dict, issues)
            if 'script-src' in csp_dict:
                script_src_values = csp_dict['script-src']
                script_src_check(script_src_values, issues)
            if 'object-src' in csp_dict:
                object_src_values = csp_dict['object-src']
                object_src_check(object_src_values, issues)
            if 'img-src' in csp_dict:
                img_src_values = csp_dict['img-src']
                img_src_check(img_src_values, issues)
            if 'media-src' in csp_dict:
                media_src_values = csp_dict['media-src']
                media_src_check(media_src_values, issues)
            if 'base-uri' in csp_dict:
                base_uri_values = csp_dict['base-uri']
                base_uri_check(base_uri_values, issues)
            if 'base-uri' not in csp_dict:
                issues.append("base-uri is missing.")
            if 'style-src' in csp_dict:
                style_src_values = csp_dict['style-src']
                style_src_check(style_src_values, issues)
            if 'font-src' in csp_dict:
                font_src_values = csp_dict['font-src']
                font_src_check(font_src_values, issues)
            if 'frame-src' in csp_dict:
                frame_src_values = csp_dict['frame-src']
                frame_src_check(frame_src_values, issues)
            for issue in issues:
                misconfigurations[issue] += 1
            for directive in csp_dict.keys():
                # If issues related to the directive exist, increment its misconfiguration count
                if any(directive in issue for issue in issues):
                    directives_misconfigured[directive] += 1
        elif(csp_string == "No CSP found on this URL." or csp_string == "The CSP is set to report-only and is not enforced, so it will not affect the page's security."):
            issues.append(csp_string)
            misconfigurations[csp_string] += 1
        domain_issues[domain] = issues
    return  misconfigurations, directives_misconfigured, domain_issues

def report_common_misconfigurations(misconfigurations, directives_misconfigured):
    # Sort misconfigurations by frequency
    sorted_misconfigurations = sorted(misconfigurations.items(), key=lambda x: x[1], reverse=True)
    issues, issue_counts = zip(*sorted_misconfigurations)
    print("\nMost Common CSP Misconfigurations:")
    for issue, count in sorted_misconfigurations:
        print(f"{issue}: {count} occurrences")
    plt.figure(figsize=(15, len(issues) * 0.8))
    plt.barh(issues, issue_counts, color="#1f77b4", edgecolor="black")
    plt.gca().invert_yaxis()  # Invert Y-axis for better readability
    plt.title("Most Common CSP Misconfigurations", fontsize=16, fontweight="bold")
    plt.xlabel("Number of Occurrences", fontsize=12)
    plt.ylabel("Misconfiguration Issues", fontsize=12)
    plt.grid(axis="x", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plot = os.path.join(".", "Most_Common_CSP_Issues.png")
    plt.savefig(plot)
    plt.close()
    # Sort directives by frequency of misconfiguration
    sorted_directives = sorted(directives_misconfigured.items(), key=lambda x: x[1], reverse=True)
    directives, directive_counts = zip(*sorted_directives)
    print("\nDirectives Most Frequently Misconfigured:")
    for directive, count in sorted_directives:
        print(f"{directive}: misconfigured in {count} policies")
    plt.figure(figsize=(10, 6))
    plt.barh(directives, directive_counts, color="#ff7f0e", edgecolor="black")
    plt.gca().invert_yaxis()  # Invert Y-axis for better readability
    plt.title("Directives Most Frequently Misconfigured", fontsize=16, fontweight="bold")
    plt.xlabel("Number of Policies", fontsize=12)
    plt.ylabel("Directives", fontsize=12)
    plt.grid(axis="x", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plot = os.path.join(".", "Directives_Most_Frequently_Misconfigured.png")
    plt.savefig(plot)
    plt.close()

def evaluate_csp_versions(csp_policies):
    csp_versions = {'CSP Level 1': 0, 'CSP Level 2': 0, 'CSP Level 3': 0}
    advanced_feature_usage = {'nonces': 0, 'hashes': 0, 'strict-dynamic': 0}

    for domain, csp_string in csp_policies.items():
        csp_version = 'CSP Level 1'  # Default to CSP Level 1
        uses_nonce = False
        uses_hash = False
        uses_strict_dynamic = False

        if csp_string != "No CSP found on this URL." and \
           csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security." and \
           csp_string != "Error fetching URL.":
            csp_dict = parse_csp(csp_string)
            
            # Check for CSP Level 2 and Level 3 features
            csp_level_2_directives = ['child-src', 'form-action', 'frame-ancestors', 'plugin-types', 'report-to']
            csp_level_3_directives = ['worker-src', 'manifest-src', 'prefetch-src', 'navigate-to']

            directives = csp_dict.keys()
            # Check for nonces, hashes, and 'strict-dynamic'
            for directive_name, directive_values in csp_dict.items():
                # Check for nonces
                if any(value.startswith("'nonce-") for value in directive_values):
                    uses_nonce = True
                # Check for hashes
                if any(value.startswith(("'sha256-", "'sha384-", "'sha512-")) for value in directive_values):
                    uses_hash = True
                # Check for 'strict-dynamic'
                if "'strict-dynamic'" in directive_values:
                    uses_strict_dynamic = True

            # Update CSP version based on features
            if uses_nonce or uses_hash or any(directive in csp_level_2_directives for directive in directives):
                csp_version = 'CSP Level 2'
            if uses_strict_dynamic or any(directive in csp_level_3_directives for directive in directives):
                csp_version = 'CSP Level 3'

            # Update counts
            csp_versions[csp_version] += 1
            if uses_nonce:
                advanced_feature_usage['nonces'] += 1
            if uses_hash:
                advanced_feature_usage['hashes'] += 1
            if uses_strict_dynamic:
                advanced_feature_usage['strict-dynamic'] += 1
        else:
            # Policies without enforced CSP are not counted towards CSP version analysis
            continue

    return csp_versions, advanced_feature_usage

def report_csp_versions_and_features(csp_versions, advanced_feature_usage):
    print("\nCSP Version Adoption:")
    total_policies = sum(csp_versions.values())
    for version, count in csp_versions.items():
        percentage = (count / total_policies) * 100 if total_policies > 0 else 0
        print(f"{version}: {count} policies ({percentage:.2f}%)")
    
    versions = list(csp_versions.keys())
    version_counts = list(csp_versions.values())
    version_percentages = [(count / total_policies) * 100 if total_policies > 0 else 0 for count in version_counts]

    plt.figure(figsize=(8, 6))
    wedges, texts, autotexts = plt.pie(version_percentages, labels=versions, autopct="%1.1f%%", startangle=140,
                                       textprops={'fontsize': 12}, colors=["#1f77b4", "#ff7f0e", "#2ca02c"])
    plt.title("CSP Version Adoption", fontsize=16, fontweight="bold")
    plt.tight_layout()
    plot = os.path.join(".", "CSP_Version.png")
    plt.savefig(plot)
    plt.close()
    
    print("\nAdvanced CSP Features Usage:")
    for feature, count in advanced_feature_usage.items():
        percentage = (count / total_policies) * 100 if total_policies > 0 else 0
        print(f"{feature.replace('-', ' ').capitalize()}: {count} policies ({percentage:.2f}%)")
    
    features = [feature.replace('-', ' ').capitalize() for feature in advanced_feature_usage.keys()]
    feature_counts = list(advanced_feature_usage.values())
    feature_percentages = [(count / total_policies) * 100 if total_policies > 0 else 0 for count in feature_counts]

    plt.figure(figsize=(12, 6))
    bars = plt.bar(features, feature_percentages, color="#ff7f0e", edgecolor="black")
    plt.title("Advanced CSP Features Usage", fontsize=16, fontweight="bold")
    plt.xlabel("Features", fontsize=12)
    plt.ylabel("Percentage of Policies (%)", fontsize=12)
    plt.xticks(rotation=45, fontsize=10, ha="right")
    plt.grid(axis="y", linestyle="--", alpha=0.7)

    # Add values above bars
    for bar, percentage in zip(bars, feature_percentages):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, f"{percentage:.1f}%", 
                 ha="center", va="bottom", fontsize=10)

    plt.tight_layout()
    plot = os.path.join(".", "CSP_Advanced_Features.png")
    plt.savefig(plot)
    plt.close()

def evaluate_directive_coverage(csp_policies):
    """
    Evaluates which CSP directives are most commonly used and which are often omitted.

    Returns:
        directive_usage_count (Counter): Counts of each directive across all policies.
        total_policies (int): Total number of policies analyzed.
    """
    directive_usage_count = Counter()
    total_policies = 0

    for domain, csp_string in csp_policies.items():
        if csp_string == "No CSP found on this URL." or \
           csp_string == "The CSP is set to report-only and is not enforced, so it will not affect the page's security." or \
           csp_string == "Error fetching URL.":
            continue  # Skip domains without enforced CSP

        csp_dict = parse_csp(csp_string)
        directives = csp_dict.keys()
        directive_usage_count.update(directives)
        total_policies += 1

    return directive_usage_count, total_policies

def report_directive_coverage(directive_usage_count, total_policies):
    """
    Reports which CSP directives are most commonly used and which are often omitted.

    Args:
        directive_usage_count (Counter): Counts of each directive across all policies.
        total_policies (int): Total number of policies analyzed.
    """
    print("\nDirective Coverage Analysis:")
    print(f"Total policies analyzed: {total_policies}")

    # Calculate the percentage of policies that include each directive
    directive_percentages = {
        directive: (count / total_policies) * 100
        for directive, count in directive_usage_count.items()
    }

    # Sort directives by usage frequency
    sorted_directives = sorted(directive_percentages.items(), key=lambda x: x[1], reverse=True)

    print("\nMost Commonly Used Directives:")
    for directive, percentage in sorted_directives:
        print(f"{directive}: used in {directive_usage_count[directive]} policies ({percentage:.2f}%)")

    # Identify directives that are often omitted (used in less than 10% of policies)
    omitted_directives = [
        (directive, percentage) for directive, percentage in directive_percentages.items() if percentage < 10
    ]

    if omitted_directives:
        print("\nDirectives Often Omitted (used in less than 10% of policies):")
        for directive, percentage in omitted_directives:
            print(f"{directive}: used in {directive_usage_count[directive]} policies ({percentage:.2f}%)")
    else:
        print("\nNo directives were used in less than 10% of policies.")
    
    # Visualization for Most Commonly Used Directives
    directives, percentages = zip(*sorted_directives)
    counts = [directive_usage_count[directive] for directive in directives]

    plt.figure(figsize=(12, 6))
    bars = plt.bar(directives, percentages, color="#1f77b4", edgecolor="black")
    plt.title("Most Commonly Used CSP Directives", fontsize=16, fontweight="bold")
    plt.xlabel("Directives", fontsize=12)
    plt.ylabel("Percentage of Policies (%)", fontsize=12)
    plt.xticks(rotation=45, fontsize=10, ha="right")
    plt.grid(axis="y", linestyle="--", alpha=0.7)

    # Add values above bars
    for bar, percentage in zip(bars, percentages):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, f"{percentage:.1f}%", 
                 ha="center", va="bottom", fontsize=10)

    plt.tight_layout()
    plot = os.path.join(".", "Most_commonly_used_directives.png")
    plt.savefig(plot)
    plt.close()

    # Visualization for Omitted Directives (if any)
    if omitted_directives:
        omitted_directives, omitted_percentages = zip(*omitted_directives)
        omitted_counts = [directive_usage_count[directive] for directive in omitted_directives]

        plt.figure(figsize=(12, 6))
        bars = plt.bar(omitted_directives, omitted_percentages, color="#d62728", edgecolor="black")
        plt.title("Directives Often Omitted (Less than 10% Usage)", fontsize=16, fontweight="bold")
        plt.xlabel("Directives", fontsize=12)
        plt.ylabel("Percentage of Policies (%)", fontsize=12)
        plt.xticks(rotation=45, fontsize=10, ha="right")
        plt.grid(axis="y", linestyle="--", alpha=0.7)

        # Add values above bars
        for bar, percentage in zip(bars, omitted_percentages):
            plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, f"{percentage:.1f}%", 
                     ha="center", va="bottom", fontsize=10)

        plt.tight_layout()
        plot = os.path.join(".", "Omitted_directives.png")
        plt.savefig(plot)
        plt.close()

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
        #print(f"Fetching CSP from {url}")
        csp_string = fetch_csp(url)
        csp_policies[url] = csp_string
    return csp_policies

def parse_and_convert_csp_policies(csp_policies):
    """
    Parses CSP policies and converts them to sets of directive-value pairs.
    Handles pages with no CSP or report-only CSP.
    """
    csp_dicts = {}
    csp_sets = {}
    for url, csp_string in csp_policies.items():
        if csp_string and "Error fetching URL." not in csp_string:
            if "No CSP found on this URL." in csp_string or "The CSP is set to report-only" in csp_string:
                # Handle pages with no CSP or report-only CSP
                csp_dicts[url] = "No CSP or Report-Only CSP"
                csp_sets[url] = {"No CSP or Report-Only CSP"}
            else:
                # Parse valid CSPs
                csp_dict = parse_csp(csp_string)
                csp_dicts[url] = csp_dict
                csp_sets[url] = csp_dict_to_set(csp_dict)
        else:
            # Error fetching URL
            csp_dicts[url] = "Error"
            csp_sets[url] = set()
    return csp_dicts, csp_sets

def compute_identical_policies(csp_dicts):
    """
    Determines how many pages have identical CSP policies.
    """
    csp_strings = [str(csp_dict) for csp_dict in csp_dicts.values() if csp_dict != "Error"]
    unique_policies = set(csp_strings)
    identical_count = len(csp_strings) - len(unique_policies)

    #print(f"\nNumber of identical CSP policies: {identical_count}")
    return identical_count

def compute_pairwise_similarities(csp_sets):
    """
    Computes pairwise similarities between CSP policies.
    """
    urls = [url for url in csp_sets.keys() if csp_sets[url] != set()]
    similarities = []
    url_pairs = list(itertools.combinations(urls, 2))
    similarity_matrix = {}
    for url1, url2 in url_pairs:
        set1 = csp_sets[url1]
        set2 = csp_sets[url2]
        similarity = compute_similarity(set1, set2)
        similarities.append(similarity)
        similarity_matrix[(url1, url2)] = similarity
        #print(f"Similarity between {url1} and {url2}: {similarity:.4f}")
    return similarities, similarity_matrix

def calculate_overall_consistency(similarities):
    """
    Calculates the overall consistency metric.
    """
    if similarities:
        overall_consistency = sum(similarities) / len(similarities)
    else:
        overall_consistency = 1.0  # Only one page or no pairwise comparisons possible
    #print(f"\nOverall Consistency Metric: {overall_consistency:.10f}")
    return overall_consistency

def identify_misconfigurations(urls):
    """
    Identifies misconfigurations in the CSP policies of URLs.
    """
    misconfigurations = {}
    for url in urls:
        issues = eval_csp(url)
        if "Error fetching URL." in issues :
            continue
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

def analyze_csp_consistency(file_path):
    """
    Analyzes the CSP consistency across multiple pages.
    """
    # Read URLs from the file
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    # Fetch CSP Policies
    csp_policies = fetch_csp_policies(urls)

    # Parse and Convert CSP Policies
    csp_dicts, csp_sets = parse_and_convert_csp_policies(csp_policies)
    
    # Compute Identical Policies
    identical_count = compute_identical_policies(csp_dicts)

    # Compute Pairwise Similarities
    similarities, similarity_matrix = compute_pairwise_similarities(csp_sets)

    # Calculate Overall Consistency Metric
    overall_consistency = calculate_overall_consistency(similarities)

    # Identify Misconfigurations
    misconfigurations = {}
    for url, csp_string in csp_policies.items():
        if csp_string != "Error fetching URL." :
            misconfigurations[url] = eval_csp(csp_string)

    # Compare Misconfigurations Between Main Page and Subpages
    misconfig_comparison = compare_misconfigurations(misconfigurations)

    # Return results
    results = {
        'overall_consistency': overall_consistency,
        'similarity_matrix': similarity_matrix,
        'misconfigurations': misconfigurations,
        'misconfig_comparison': misconfig_comparison,
        'identical_policies': identical_count
    }
    print(f"\nOverall Consistency Metric: {results['overall_consistency']:.4f}")
    print(f"Number of identical CSP policies: {results['identical_policies']}")
    # Print Misconfiguration Comparison
    print(results['misconfig_comparison'])
    return results

def process_directory(directory_path):
    """
    Processes all .txt files in a directory and performs CSP analysis for each domain.
    """
    domain_results = {}
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):
            domain = filename.replace('.txt', '')  # Use the filename as the domain
            file_path = os.path.join(directory_path, filename)
            print(f"Processing domain: {domain}")
            domain_results[domain] = analyze_csp_consistency(file_path)
    return domain_results

def visualize_results(domain_results, output_dir="."):
    """
    Visualizes overall consistency and misconfiguration comparisons for all domains
    and saves the plots in the specified directory.

    Args:
        domain_results (dict): Analysis results for each domain.
        output_dir (str): Directory to save the plots.
    """
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Prepare data for visualization
    domains = list(domain_results.keys())
    #print(domain_results["cnn.com"]['misconfigurations'])
    consistencies = [domain_results[domain]['overall_consistency'] for domain in domains]
    #misconfig_counts = [len(domain_results[domain]['misconfigurations'][domains[0]]) for domain in domains]

    # Visualize Overall Consistency
    consistency_plot_path = os.path.join(output_dir, "overall_consistency.png")
    plt.figure(figsize=(20, 6))
    plt.bar(domains, consistencies, color='blue', edgecolor='black')
    plt.title("Overall Consistency Across Domains", fontsize=16, fontweight="bold")
    plt.xlabel("Domains", fontsize=12)
    plt.ylabel("Consistency Metric", fontsize=12)
    plt.xticks(rotation=90, ha='center', fontsize=8)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(consistency_plot_path)  # Save the plot
    plt.close()  # Close the plot to free memory
    print(f"Overall consistency plot saved at: {consistency_plot_path}")

    # Visualize Misconfiguration Counts
    more_issues = []
    fewer_issues = []
    same_issues = []

    for domain, results in domain_results.items():
        misconfig_comparison = results.get("misconfig_comparison", "")
        if "Subpages have more misconfigurations" in misconfig_comparison:
            more_issues.append(domain)
        elif "Subpages have fewer misconfigurations" in misconfig_comparison:
            fewer_issues.append(domain)
        elif "Subpages have the same number of misconfigurations" in misconfig_comparison:
            same_issues.append(domain)

    # Visualize classified domains
    labels = ["Subpages > Main Page", "Subpages < Main Page", "Subpages = Main Page"]
    counts = [len(more_issues), len(fewer_issues), len(same_issues)]

    plt.figure(figsize=(8, 6))
    plt.bar(labels, counts, color=['red', 'green', 'blue'], edgecolor='black')
    plt.title("Comparison of Misconfigurations: Subpages vs. Main Page", fontsize=16, fontweight="bold")
    plt.xlabel("Comparison (Subpages vs. Main Page)", fontsize=12)
    plt.ylabel("Number of Domains", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()

    # Save the plot
    classification_plot_path = os.path.join(output_dir, "domain_classification.png")
    plt.savefig(classification_plot_path)
    plt.close()
    print(f"Domain classification plot saved at: {classification_plot_path}")

def main():
    # List of URLs to check, this should be done automatically by fetching the top N most visited sites
    #analyze_csp_prevalence()
    domains_file = '100MostVisitedSites.txt'

    with open(domains_file, 'r', encoding='utf-8') as file:
        domains = [line.strip() for line in file if line.strip()]

    #Step 1: Collect CSP Policies
    csp_policies = collect_csp_policies(domains)
    
    # Analyze CSP prevalence
    analyze_csp_prevalence(csp_policies)

    # Step 2: Evaluate CSP Policies
    misconfigurations, directives_misconfigured, domain_issues = eval_csp_v2(csp_policies)

    # Step 3: Report Findings
    report_common_misconfigurations(misconfigurations, directives_misconfigured)
    
    # Evaluate CSP Versions and Advanced Features
    csp_versions, advanced_feature_usage = evaluate_csp_versions(csp_policies)

    # Report CSP Versions and Advanced Features
    report_csp_versions_and_features(csp_versions, advanced_feature_usage)
    
    # Evaluate Directive Coverage
    directive_usage_count, total_policies = evaluate_directive_coverage(csp_policies)

    # Report Directive Coverage
    report_directive_coverage(directive_usage_count, total_policies)
    
def main2():
    domain_results = process_directory("./crawler/google_results")
    visualize_results(domain_results)
    
if __name__ == "__main__":
    main()
