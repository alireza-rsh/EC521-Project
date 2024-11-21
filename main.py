import requests
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
from collections import defaultdict
import re

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
        # Send request to the URL
        response = requests.get(url)
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
        return ""

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

def eval_csp(url):
    issues = []
    csp_string = fetch_csp(url)
    csp_dict = []
    if csp_string != "No CSP found on this URL." and csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security.":
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
        if csp_string != "No CSP found on this URL." and csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security.":
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
        else:
            issues.append(csp_string)
            misconfigurations[csp_string] += 1
        domain_issues[domain] = issues
    return  misconfigurations, directives_misconfigured, domain_issues

def report_common_misconfigurations(misconfigurations, directives_misconfigured):
    # Sort misconfigurations by frequency
    sorted_misconfigurations = sorted(misconfigurations.items(), key=lambda x: x[1], reverse=True)
    print("\nMost Common CSP Misconfigurations:")
    for issue, count in sorted_misconfigurations:
        print(f"{issue}: {count} occurrences")

    # Sort directives by frequency of misconfiguration
    sorted_directives = sorted(directives_misconfigured.items(), key=lambda x: x[1], reverse=True)
    print("\nDirectives Most Frequently Misconfigured:")
    for directive, count in sorted_directives:
        print(f"{directive}: misconfigured in {count} policies")

def main():
    # List of URLs to check, this should be done automatically by fetching the top N most visited sites
    #analyze_csp_prevalence()
    domains_file = '100MostVisitedSites.txt'

    with open(domains_file, 'r', encoding='utf-8') as file:
        domains = [line.strip() for line in file if line.strip()]

    # Step 1: Collect CSP Policies
    csp_policies = collect_csp_policies(domains)

    # Step 2: Evaluate CSP Policies
    misconfigurations, directives_misconfigured, domain_issues = eval_csp_v2(csp_policies)

    # Step 3: Report Findings
    report_common_misconfigurations(misconfigurations, directives_misconfigured)
    print("-----------------------------------------------------------------------------------------")
    # Analyze CSP prevalence
    analyze_csp_prevalence(csp_policies)

if __name__ == "__main__":
    main()
