#!/usr/bin/env python3
import argparse
import re
import time
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs, unquote

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    print("Error: 'requests' library is not installed. Please install it with 'pip install requests requests[socks]'.")
    exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: 'BeautifulSoup4' library is not installed. Please install it with 'pip install beautifulsoup4 lxml'.")
    exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("Warning: 'colorama' library not found. Output will not be colored. Install with 'pip install colorama'.")

    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = DummyColor()
    Style = DummyColor()

VERSION = "1.0.0" 

class MinerError(Exception):
    """Base class for exceptions in this module."""
    pass

class RequestError(MinerError):
    """For network request errors."""
    def __init__(self, message, original_exception=None):
        super().__init__(message)
        self.original_exception = original_exception

class UrlParseError(MinerError):
    """For URL parsing errors."""
    def __init__(self, message, original_exception=None):
        super().__init__(message)
        self.original_exception = original_exception

class InvalidBaseUrl(MinerError):
    """For invalid base URL."""
    pass

# --- Banner ---
def print_banner():
    banner_text = r"""
$$$$$$$\                                            $$\                 $$\                     
$$  __$$\                                           \__|                $$ |                    
$$ |  $$ |$$$$$$\   $$$$$$\  $$$$$$\  $$$$$$\$$$$\  $$\ $$$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$\  
$$$$$$$  |\____$$\ $$  __$$\ \____$$\ $$  _$$  _$$\ $$ |$$  __$$\ $$  __$$ |$$  __$$\ $$  __$$\ 
$$  ____/ $$$$$$$ |$$ |  \__|$$$$$$$ |$$ / $$ / $$ |$$ |$$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|
$$ |     $$  __$$ |$$ |     $$  __$$ |$$ | $$ | $$ |$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
$$ |     \$$$$$$$ |$$ |     \$$$$$$$ |$$ | $$ | $$ |$$ |$$ |  $$ |\$$$$$$$ |\$$$$$$$\ $$ |      
\__|      \_______|\__|      \_______|\__| \__| \__|\__|\__|  \__| \_______| \_______|\__|      
                                                                                          
    """
    print(Fore.CYAN + Style.BRIGHT + banner_text)
    print(f"{' ' * 30}A Python tool to gather web application parameters, By Remmy")
    print(f"{' ' * 27}{Fore.LIGHTBLACK_EX}Version: {VERSION}{Style.RESET_ALL}")
    print()

def is_potential_param_name(s: str) -> bool:
    """
    Validates if a string is a potential parameter name.
    - Length between 2 and 50.
    - Starts with a letter.
    - Contains alphanumeric, underscore, hyphen, or brackets.
    - No spaces.
    - Not purely numeric.
    """
    if not s or not (2 <= len(s) <= 50):
        return False
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_\[\]\-]*$", s):
        return False
    if " " in s or s.isdigit():
        return False
    return True

def extract_params_from_url_query(url_str: str) -> set[str]:
    """Extracts parameter names from a URL's query string."""
    params = set()
    try:
        parsed_url = urlparse(url_str)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        for key in query_params:
            if is_potential_param_name(key):
                params.add(key)
    except Exception:
        pass
    return params

def extract_from_html_and_links(
    body: str,
    base_url_str: str,
    is_aggressive_mode_enabled: bool
) -> tuple[set[str], list[tuple[str, str]], set[str]]:
    """
    Extracts parameters and links from HTML content.
    Returns: (standard_params, links_typed, aggressive_params)
             links_typed is a list of ('navigation'/'script', absolute_url_str)
    """
    standard_params = set()
    links = []
    aggressive_html_params = set()
    
    try:
        soup = BeautifulSoup(body, 'lxml')

        # Standard parameters from form elements
        form_element_selectors = ["input[name]", "textarea[name]", "select[name]", "button[name]"]
        for selector_str in form_element_selectors:
            for element in soup.select(selector_str):
                name = element.get("name")
                if name and name.strip() and is_potential_param_name(name.strip()):
                    standard_params.add(name.strip())

        # Navigation links: a[href]
        for element in soup.select("a[href]"):
            href = element.get("href")
            if href:
                try:
                    abs_url = urljoin(base_url_str, href.strip())
                    if urlparse(abs_url).scheme in ['http', 'https']:
                        links.append(('navigation', abs_url))
                except Exception: pass

        # Script links: script[src]
        for element in soup.select("script[src]"):
            src = element.get("src")
            if src:
                try:
                    abs_url = urljoin(base_url_str, src.strip())
                    if urlparse(abs_url).scheme in ['http', 'https']:
                        links.append(('script', abs_url))
                except Exception: pass

        # Inline scripts
        for element in soup.select("script"):
            if not element.get("src"): # Only inline
                script_content = element.string or element.get_text()
                if script_content:
                    js_params = extract_from_js(script_content)
                    for param in js_params: # Assumes extract_from_js already validates
                        standard_params.add(param)

        # Aggressive HTML parameter extraction
        if is_aggressive_mode_enabled:
            for element in soup.find_all(True): # Iterate over all elements
                attrs_to_check_aggressively = {}
                if element.get("id"): attrs_to_check_aggressively["id"] = element.get("id")
                # Name attribute on non-form elements (form ones are standard)
                if element.name not in ['input', 'textarea', 'select', 'button'] and element.get("name"):
                    attrs_to_check_aggressively["name"] = element.get("name")
                if element.name == "label" and element.get("for"): attrs_to_check_aggressively["for"] = element.get("for")
                if element.name == "option" and element.get("value"): attrs_to_check_aggressively["option_value"] = element.get("value")

                for attr_key, attr_val in attrs_to_check_aggressively.items():
                    if attr_val and attr_val.strip() and is_potential_param_name(attr_val.strip()):
                        # For 'name', ensure it's not already a standard param from a form context
                        if attr_key == "name" and attr_val.strip() in standard_params:
                            continue
                        aggressive_html_params.add(attr_val.strip())
                
                # data-* attributes
                for attr_name in element.attrs:
                    if attr_name.startswith("data-") and len(attr_name) > 5:
                        potential_param = attr_name[5:].strip()
                        if potential_param and is_potential_param_name(potential_param):
                            aggressive_html_params.add(potential_param)
                        
    except Exception: # Robustness for parsing errors
        pass
    return standard_params, links, aggressive_html_params

def extract_from_js(body: str) -> set[str]:
    """Extracts potential parameter names from JavaScript code using regex."""
    params = set()
    # Regexes are inspired by the Rust version, adapted for Python.
    # Group 1 in each regex should capture the potential parameter name.
    js_param_regexes_tuples = [
        (re.compile(r'(?i)\b(?:params?|query|data|form_data|payload|args|config|settings|options|body|json)\s*\.\s*([a-zA-Z_][\w_]{2,})\b'), 1),
        (re.compile(r'''(?i)['"]([a-zA-Z_][\w_]{2,})['"]\s*:\s*(?:[^,'"}\]]|['"`].*?['"`]|\d+\.?\d*|true|false|null|\{[^\{\}]*?\}|\[[^\[\]]*?\])'''), 1),
        (re.compile(r'(?i)\b([a-zA-Z_][\w_]{2,})\s*:\s*(?:[^\s,"}\]]|[\'"`].*?[\'"`]|\d+\.?\d*|true|false|null|\{[^\{\}]*?\}|\[[^\[\]]*?\])'), 1),
        (re.compile(r'(?i)\.(?:append|set)\s*\(\s*[\'"]([\w_\[\]\-]{2,})[\'"]\s*,'), 1),
        (re.compile(r"(?i)get(?:ElementById|Attribute(?:Node)?)\s*\(\s*['\"]([\w\-]{3,})['\"]\s*\)"), 1),
        (re.compile(r"(?i)setAttributes?\s*\(\s*['\"]([\w\-]{3,})['\"]\s*,"), 1),
        (re.compile(r"""(?i)querySelector(?:All)?\s*\(\s*['"](?:[^'"]*\[name=['"]([^'"]+)['"]\])['"]\s*\)"""), 1),
        (re.compile(r'(?i)(?:var|let|const)\s+([a-zA-Z_][\w_]{3,})\s*=\s*(?:[\'"`{\[\]]|fetch|axios|\$\.(?:ajax|get|post))'), 1),
        (re.compile(r'(?:[?&])([\w_\[\]\-]{3,})=[^&\'"`\s<>;]*'), 1),
        (re.compile(r'''new\s+URLSearchParams\s*\(\s*(?:['"]\??([^'"\s]+)['"]|`\??([^`\s]+)`)?\s*\)'''), None), # Special: groups 1 or 2
    ]

    for regex, group_idx in js_param_regexes_tuples:
        try:
            for match in regex.finditer(body):
                param_str_raw = None
                if group_idx is not None: # Standard case with one capture group
                    if match.lastindex and match.lastindex >= group_idx:
                        param_str_raw = match.group(group_idx)
                elif "URLSearchParams" in regex.pattern: # Special handling for URLSearchParams
                    param_str_raw = match.group(1) if match.group(1) else match.group(2)


                if not param_str_raw: continue
                
                param_str_decoded = ""
                try:
                    param_str_decoded = unquote(param_str_raw.strip())
                except Exception: # unquote can fail on malformed strings
                    param_str_decoded = param_str_raw.strip()


                if "URLSearchParams" in regex.pattern: # If it's the full query string from URLSearchParams
                    try:
                        temp_parsed_query = parse_qs(param_str_decoded, keep_blank_values=True)
                        for p_key in temp_parsed_query:
                            if is_potential_param_name(p_key):
                                params.add(p_key)
                    except Exception: pass
                elif is_potential_param_name(param_str_decoded):
                    params.add(param_str_decoded)
        except Exception: # Catch errors during regex processing for a specific regex
            continue
    return params

# --- Core Processing Function ---
def fetch_and_process_url(
    session: requests.Session,
    url_str: str,
    base_domain: str,
    is_aggressive_html_mode: bool,
    standard_params_set: set,
    aggressive_params_set: set,
) -> deque[str]:
    """
    Fetches a URL, processes its content for parameters and links, and updates sets.
    Returns: js_links_for_passive_scan
    """
    new_std_params_on_page = 0
    new_aggressive_params_on_page = 0
    js_links_for_passive_scan = deque()

    try:
        # 1. Extract params from the URL query itself
        params_from_url = extract_params_from_url_query(url_str)
        for param in params_from_url:
            if param not in standard_params_set:
                standard_params_set.add(param)
                new_std_params_on_page += 1
    except Exception: pass


    # 2. Fetch the URL
    try:
        response = session.get(url_str)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        print(f"[{Fore.RED}E{Style.RESET_ALL}] Failed to fetch {url_str}")
        return js_links_for_passive_scan

    # 3. Process content based on type
    content_type = response.headers.get('Content-Type', '').lower()
    try:
        body = response.text
    except Exception:
        return js_links_for_passive_scan


    if 'html' in content_type:
        html_std_params, page_links_typed, html_agg_params = extract_from_html_and_links(
            body, url_str, is_aggressive_html_mode
        )

        for param in html_std_params:
            if param not in standard_params_set:
                standard_params_set.add(param)
                new_std_params_on_page += 1
        
        if is_aggressive_html_mode:
            for param in html_agg_params:
                if param not in aggressive_params_set:
                    aggressive_params_set.add(param)
                    new_aggressive_params_on_page += 1
        
        # In single-threaded mode, we only care about JS links from HTML pages
        # as we won't actively crawl navigation links in this simplified version.
        for link_type, link_url_str in page_links_typed:
            if link_type == 'script':
                try:
                    parsed_link_url = urlparse(link_url_str)
                    if parsed_link_url.scheme in ['http', 'https'] and parsed_link_url.netloc == base_domain:
                        js_links_for_passive_scan.append(link_url_str)
                except Exception: pass

    elif 'javascript' in content_type or 'json' in content_type:
        js_params = extract_from_js(body)
        for param in js_params:
            if param not in standard_params_set:
                standard_params_set.add(param)
                new_std_params_on_page += 1
            
    if new_std_params_on_page > 0:
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Found {new_std_params_on_page} new standard parameters from {url_str}")
    if is_aggressive_html_mode and new_aggressive_params_on_page > 0:
        print(f"[{Fore.MAGENTA}A{Style.RESET_ALL}] Found {new_aggressive_params_on_page} new aggressive HTML parameters from {url_str}")

    return js_links_for_passive_scan

# --- Main Application Logic ---
def main():
    parser = argparse.ArgumentParser(
        description="ParaMinder: A Python tool to gather web application parameters - By Remmy",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Example usage:
  python3 %(prog)s -t https://example.com -o params.txt
  python3 %(prog)s -t https://test.com --proxy http://127.0.0.1:8080 -m

Notes:
- For SOCKS proxy, ensure 'requests[socks]' is installed: pip install requests[socks]
- For faster HTML parsing, ensure 'lxml' is installed: pip install lxml
"""
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL to analyze (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Output file to save found parameters")
    parser.add_argument("--proxy", help="Proxy server URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)")
    parser.add_argument("--user-agent", default=f"ParamMinerPython/{VERSION}", help="User-Agent string")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("-m", "--aggressive-mode", action="store_true", help="Enable aggressive HTML parameter extraction")
    parser.add_argument("--no-banner", action="store_true", help="Don't print banner")
    parser.add_argument("--danger-accept-invalid-certs", action="store_true", help="Ignore SSL certificate errors (USE WITH CAUTION)")
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    args = parser.parse_args()

    if not args.no_banner: print_banner()
    if args.aggressive_mode: print(f"[{Fore.MAGENTA}*{Style.RESET_ALL}] Aggressive HTML parameter guessing mode enabled.")
    
    if args.danger_accept_invalid_certs:
        print(f"[{Fore.YELLOW}!{Style.RESET_ALL}] SSL certificate verification disabled. This is insecure.")
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except AttributeError:
            pass


    http_session = requests.Session()
    http_session.headers.update({"User-Agent": args.user_agent})
    http_session.timeout = args.timeout
    http_session.verify = not args.danger_accept_invalid_certs
    http_session.max_redirects = 5

    if args.proxy:
        print(f"[{Fore.YELLOW}*{Style.RESET_ALL}] Using proxy: {Fore.CYAN}{args.proxy}{Style.RESET_ALL}")
        http_session.proxies = {"http": args.proxy, "https": args.proxy}

    try:
        parsed_start_url = urlparse(args.target)
        if not parsed_start_url.scheme or not parsed_start_url.netloc:
            raise InvalidBaseUrl(f"Invalid target URL: {args.target}. Must include scheme and hostname.")
        start_url_str = parsed_start_url.geturl()
        base_domain = parsed_start_url.netloc
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}"); return

    standard_params_global, aggressive_params_global = set(), set()
    
    passive_js_to_scan_queue = deque()
    visited_passive_js_urls = set() # To avoid redundant processing of JS files

    print(f"[{Fore.CYAN}*{Style.RESET_ALL}] Starting single-page and JS file passive scan...")
    print(f"[{Fore.YELLOW} P {Style.RESET_ALL}] Fetching (Passive): {start_url_str}")
    try:
        js_links_from_initial_page = fetch_and_process_url(
            http_session, start_url_str, base_domain, args.aggressive_mode,
            standard_params_global, aggressive_params_global
        )
        
        for js_url in js_links_from_initial_page:
            if js_url not in visited_passive_js_urls:
                passive_js_to_scan_queue.append(js_url)
                visited_passive_js_urls.add(js_url)

    except Exception as e:
        print(f"[{Fore.RED}E{Style.RESET_ALL}] Error processing {start_url_str}: {e} (ignored)")
    print(f"[{Fore.CYAN}*{Style.RESET_ALL}] Initial page scan complete.")

    # Process collected JS files
    if passive_js_to_scan_queue:
        print(f"[{Fore.CYAN}*{Style.RESET_ALL}] Processing {len(passive_js_to_scan_queue)} discovered JavaScript files...")
        
        while passive_js_to_scan_queue:
            js_url_str = passive_js_to_scan_queue.popleft()
            
            # Domain check should have happened before adding, but as a safeguard:
            try:
                if urlparse(js_url_str).netloc != base_domain: continue
            except Exception: continue

            print(f"[{Fore.YELLOW} J {Style.RESET_ALL}] Fetching (Passive JS): {js_url_str}")
            try:
                # No new JS links from JS files, and no aggressive HTML for JS content
                fetch_and_process_url(
                    http_session, js_url_str, base_domain, False,
                    standard_params_global, aggressive_params_global
                )
            except Exception as e:
                print(f"[{Fore.RED}E{Style.RESET_ALL}] Error processing JS {js_url_str}: {e} (ignored)")
        
        print(f"[{Fore.CYAN}*{Style.RESET_ALL}] JavaScript file processing complete.")

    # Final Results
    final_standard_params = sorted(list(standard_params_global))
    print(f"\n[{Fore.GREEN}*{Style.RESET_ALL}] Scan complete. Found {len(final_standard_params)} unique standard parameters:")
    for param in final_standard_params: print(f"  - {Fore.CYAN}{param}{Style.RESET_ALL}")

    if args.aggressive_mode:
        final_aggressive_params = sorted(list(aggressive_params_global))
        print(f"\n[{Fore.MAGENTA}A{Style.RESET_ALL}] Found {len(final_aggressive_params)} unique aggressively guessed HTML parameters:")
        if final_aggressive_params:
            for param in final_aggressive_params: print(f"  - {Fore.MAGENTA}{param}{Style.RESET_ALL}")

    if args.output:
        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Writing all parameters to {Fore.CYAN}{args.output}{Style.RESET_ALL}")
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                for param in final_standard_params: f.write(f"{param}\n")
                if args.aggressive_mode:
                    # Re-sort just in case, though it should be sorted from list(set)
                    final_aggressive_params_for_file = sorted(list(aggressive_params_global))
                    for param in final_aggressive_params_for_file: f.write(f"{param}\n")
        except IOError as e:
            print(f"{Fore.RED}[ERROR] Could not write to output file {args.output}: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
