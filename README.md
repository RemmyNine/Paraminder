ParamMiner 🐍
<p align="center">
<img src="[suspicious link removed]" alt="Python 3.x">
<img src="[suspicious link removed]" alt="GitHub Stars">
<img src="[suspicious link removed]" alt="License">
</p>

🎯 Project Overview
ParamMiner is a Python tool engineered for efficient web parameter discovery. It's designed to assist security researchers, penetration testers, and developers in identifying potential input points within web applications during reconnaissance and analysis phases.

This tool systematically extracts parameters directly from URL query strings, parses HTML content for form fields, and delves into linked JavaScript files for additional insights. With its specialized aggressive mode for deeper attribute analysis and built-in proxy support, ParamMiner aims to be a straightforward yet powerful addition to your web assessment toolkit.

✨ Core Capabilities
URL Query Parameter Extraction: Identifies parameters embedded directly in the target URL's query string.
HTML Form Field Discovery: Scans HTML documents to extract name attributes from common form elements like input, textarea, select, and button.
JavaScript Parameter Inference: Leverages intelligent regex patterns to uncover potential parameter names within both inline and external JavaScript resources.
Aggressive HTML Attribute Analysis: An optional mode that expands discovery by inspecting id, non-form name, for (on labels), value (on options), and data-* attributes for potential parameter names.
Proxy Integration: Supports routing all traffic through HTTP, HTTPS, or SOCKS proxies, ideal for anonymous scanning or integrating with intercepting proxies like Burp Suite.
Configurable Request Headers: Allows custom User-Agent strings and adjustable request timeouts.
SSL Verification Control: Provides an option to disable SSL certificate validation for specific testing scenarios (use with extreme caution!).
Output to File: Stores all discovered parameters in a designated text file for easy review and further processing.
Interactive Console Output: Features clear, colored console messages for real-time feedback.
🚀 Getting Started
Here's how you can get ParamMiner up and running quickly.

Prerequisites
Python 3.x (3.6 or newer is recommended)
pip (Python package installer)
Installation Steps
Clone the Repository:
Start by getting a copy of the ParamMiner source code.

Bash

git clone https://github.com/YOUR_GITHUB_USERNAME/ParamMiner.git
cd ParamMiner
(Remember to replace YOUR_GITHUB_USERNAME with your actual GitHub username.)

Install Dependencies:
ParamMiner uses a few standard Python libraries. The lxml parser is recommended for faster HTML processing, though beautifulsoup4 will gracefully fall back if lxml isn't available.

Bash

pip install -r requirements.txt
requirements.txt content:

requests
beautifulsoup4
lxml # Recommended for enhanced performance
colorama # For visual console output
📖 How to Use
ParamMiner's command-line interface is straightforward.

Basic Scan
To perform a fundamental parameter discovery on a target URL:

Bash

python3 paramminer.py -t https://your-target.com
Engaging Aggressive Mode
Activate aggressive mode (-m or --aggressive-mode) to broaden the scope of HTML attribute analysis and potentially uncover more parameters:

Bash

python3 paramminer.py -t https://your-target.com -m
Proxying Your Requests
Direct all your HTTP/S traffic through a specified proxy. This is super useful for anonymity or for integrating with your web proxies like Burp Suite.

Bash

python3 paramminer.py -t https://your-target.com --proxy http://127.0.0.1:8080
# For SOCKS proxies, ensure you've installed the 'requests[socks]' extra:
# pip install "requests[socks]"
# python3 paramminer.py -t https://your-target.com --proxy socks5://127.0.0.1:1080
Saving Your Findings
To output all discovered parameters to a text file for later analysis or integration with other tools:

Bash

python3 paramminer.py -t https://your-target.com -o found_params.txt
Customizing Requests
User-Agent: Define a specific User-Agent string:
Bash

python3 paramminer.py -t https://your-target.com --user-agent "MySecurityScanner/1.0"
Request Timeout: Adjust how long ParamMiner waits for a server response (default is 10 seconds):
Bash

python3 paramminer.py -t https://your-target.com --timeout 30.0
Bypassing SSL Certificate Verification (🛑 DANGER!)
Use this option with extreme caution: Disabling SSL certificate verification (--danger-accept-invalid-certs) makes your connection vulnerable to man-in-the-middle attacks. Only use this on trusted targets or within controlled testing environments where you understand the risks.

Bash

python3 paramminer.py -t https://your-target.com --danger-accept-invalid-certs
Combining Options
You can, of course, mix and match these options to fit your specific needs:

Bash

python3 paramminer.py -t https://your-target.com -m --proxy http://127.0.0.1:8080 -o my_scan_results.txt --user-agent "ParamHunterPro/0.2"
Complete Command-Line Arguments
usage: paramminer.py [-h] -t TARGET [-o OUTPUT] [--proxy PROXY] [--user-agent USER_AGENT] [--timeout TIMEOUT] [-m] [--no-banner] [--danger-accept-invalid-certs] [--version]

ParamMiner: A Python tool to gather web application parameters.

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target URL to analyze (e.g., https://example.com)
  -o OUTPUT, --output OUTPUT
                        Output file to save found parameters
  --proxy PROXY         Proxy server URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)
  --user-agent USER_AGENT
                        User-Agent string
  --timeout TIMEOUT     Request timeout in seconds
  -m, --aggressive-mode
                        Enable aggressive HTML parameter extraction
  --no-banner           Don't print banner
  --danger-accept-invalid-certs
                        Ignore SSL certificate errors (USE WITH CAUTION)
  --version             show program's version number and exit

Example usage:
  python3 paramminer.py -t https://example.com -o params.txt
  python3 paramminer.py -t https://test.com --proxy http://127.0.0.1:8080 -m

Notes:
- For SOCKS proxy, ensure 'requests[socks]' is installed: pip install requests[socks]
- For faster HTML parsing, ensure 'lxml' is installed: pip install lxml
