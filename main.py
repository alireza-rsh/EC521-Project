import requests
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
from collections import OrderedDict
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
        directive_values = [value.replace("'", "") for value in parts[1:]]  # Remove any single quotes

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
        issues.append("Contains 'strict-dynamic' - other source expressions are ignored, relying only on trusted dynamic scripts.")
    
    # Check for 'unsafe-eval' regardless of 'strict-dynamic'
    if "'unsafe-eval'" in script_src_values:
        issues.append("Contains 'unsafe-eval' - allows the use of eval() and similar methods, which can be exploited for XSS.")

    # If strict-dynamic is present, skip checks for wildcard (*), self, and other host sources
    if "'strict-dynamic'" not in script_src_values:
        # Check for wildcard (*)
        if '*' in script_src_values:
            issues.append("Contains wildcard '*' - allows scripts from any source, reducing security.")
        
        # Check for 'unsafe-inline'
        has_hashes = any(source.startswith("sha") for source in script_src_values)
        has_nonce = any(src.startswith("nonce-") for src in script_src_values)
        if "'unsafe-inline'" in script_src_values:
            if has_hashes or has_nonce:
                issues.append("unsafe-inline is ignored if a nonce or a hash is present.")
            else:
                issues.append("Contains 'unsafe-inline' - allows inline scripts, making it vulnerable to XSS attacks.")

        # Check for overly broad HTTPS source (e.g., 'https:' without specifying a domain)
        if any(source == 'https:' for source in script_src_values):
            issues.append("Contains broad 'https:' source - allows scripts from any HTTPS domain, which may introduce risks.")
        
        # Check if hashes are present and flag if combined with 'unsafe-inline'
        
        
        # Check if self is allowed and flag it (self is generally okay but worth noting)
        if "'self'" in script_src_values:
            issues.append("Contains 'self' - allows scripts from the same origin, generally safe but can be exploited if there is no restriction for File Uploads.")
        
        # General warning for any host URLs (http:// or https://)
        url_pattern = re.compile(r'^https?://[^\s]+')
        if any(url_pattern.match(source) for source in script_src_values):
            issues.append("Contains host URLs - ensure that no URLs in the 'script-src' serve JSONP responses or Angular libraries to prevent potential security risks.")
    
    return issues
    
def object_src_check(object_src_values, issues):
    """
    Checks for common misconfigurations in the 'object-src' directive of CSP.

    Args:
        object_src_values (list): A list of sources specified in the 'object-src' directive.
        issues (list): List to append any identified issues.
    """
    # 1. Prefer 'none' to disallow all object sources
    if 'none' not in object_src_values:
        issues.append("object-src: Should be set to 'none' to prevent loading of plugins and other objects that can be exploited.")

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
        issues.append(f"object-src: Contains protocol-relative URL '{src}' - can lead to loading objects over unintended protocols.")

    # 5. Warn if 'self' is allowed, as it permits objects from the same origin
    if 'self' in object_src_values:
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

def eval_csp(url):
    issues = []
    csp_string = fetch_csp(url)
    csp_dict =[]
    if csp_string != "No CSP found on this URL." and csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security.":
        csp_dict = parse_csp(csp_string)
        if 'script-src' in csp_dict:
            script_src_values = csp_dict['script-src']
            script_src_check(script_src_values, issues)
        if 'object-src' in csp_dict:
            object_src_values = csp_dict['object-src']
            object_src_check(object_src_values, issues)
        if 'img_src' in csp_dict:
            img_src_values = csp_dict['img_src']
            img_src_check(img_src_values, issues)
        if 'media_src' in csp_dict:
            media_src_values = csp_dict['media_src']
            media_src_check(media_src_values, issues)
        if 'base_uri' in csp_dict:
            base_uri_values = csp_dict['base_uri']
            base_uri_check(base_uri_values, issues)
    else:
        issues.append(csp_string)
    return issues

def is_valid_url(url):
    """
    Check if the url is valid.

    Parameters:
    url (str): The url to be checked.

    Returns:
    bool: True if valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def get_links(url, tag_class=None):
    """
    returns a list of all valid linked urls with no paths or duplicates
    """
    # gets all the links on a site without duplicates
    req = requests.get(url)
    soup = BeautifulSoup(req.content, 'html.parser')
    if tag_class is not None:
        links = [ urlunparse(urlparse(link.get('href'))._replace(path='',query='',params='',fragment='')) for link in soup.find_all('a',class_=tag_class)]
    else:
        links = [ urlunparse(urlparse(link.get('href'))._replace(path='',query='',params='',fragment='')) for link in soup.find_all('a')]
    no_duplicates = list(OrderedDict.fromkeys(links))
    return [ link for link in no_duplicates if is_valid_url(link) ]

def survey():
    # Get the top 100 most visited sites
    list_url = "https://en.wikipedia.org/wiki/List_of_most-visited_websites"
    links = get_links(list_url, "external text")
    csp_evals = dict()

    vuln_count = 0
    site_count = len(links)
    
    # Evaluate the CSP for each of these sites
    for url in links:
        issues = eval_csp(url)
        csp_evals[url] = issues
        vuln_count += len(issues)
    avg_vulns_per_site = vuln_count / site_count
    return csp_evals, avg_vulns_per_site

def main():
    # List of URLs to check, this should be done automatically by fetching the top N most visited sites
    csp_evals, avg_vulns_per_site = survey()
    for url in csp_evals.keys():
        print(url, csp_evals[url])
    print("Average # of vulns per site: ", avg_vulns_per_site)

if __name__ == "__main__":
    main()
