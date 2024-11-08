import requests
from bs4 import BeautifulSoup
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
        if "'unsafe-inline'" in script_src_values:
            issues.append("Contains 'unsafe-inline' - allows inline scripts, making it vulnerable to XSS attacks.")
        
        # Check for overly broad HTTPS source (e.g., 'https:' without specifying a domain)
        if any(source == 'https:' for source in script_src_values):
            issues.append("Contains broad 'https:' source - allows scripts from any HTTPS domain, which may introduce risks.")
        
        # Check if hashes are present and flag if combined with 'unsafe-inline'
        has_hashes = any(source.startswith("sha") for source in script_src_values)
        if has_hashes and "'unsafe-inline'" in script_src_values:
            issues.append("Combines 'unsafe-inline' with script hashes - 'unsafe-inline' overrides the security benefits of hashes.")
        
        # Check if self is allowed and flag it (self is generally okay but worth noting)
        if "'self'" in script_src_values:
            issues.append("Contains 'self' - allows scripts from the same origin, generally safe but can be exploited if the site is compromised.")
        
        # General warning for any host URLs (http:// or https://)
        url_pattern = re.compile(r'^https?://[^\s]+')
        if any(url_pattern.match(source) for source in script_src_values):
            issues.append("Contains host URLs - ensure that no URLs in the 'script-src' serve JSONP responses or Angular libraries to prevent potential security risks.")
    
    return issues
    
def main():

    url = 'https://developer.mozilla.org/'
    issues = []
    csp_string = fetch_csp(url)
    csp_dict =[]
    if csp_string != "No CSP found on this URL." and csp_string != "The CSP is set to report-only and is not enforced, so it will not affect the page's security.":
        csp_dict = parse_csp(csp_string)
        if 'script-src' in csp_dict:
            script_src_values = csp_dict['script-src']
            print(script_src_values) 
            script_src_check(script_src_values, issues)
            print(issues)
    else:
        issues.append(csp_string)
        print(issues)

if __name__ == "__main__":
    main()