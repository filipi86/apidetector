# Extended APIDetector with OWASP API Top 10 checks
# Author: Filipi Pires (Pull Request Version)

import requests
import concurrent.futures
import argparse
import random
import string
import difflib
import subprocess
import os
import json
from urllib.parse import urlparse

ascii_art = """
     \      _ \ _ _|      __ \   ____| __ __|  ____|   ___| __ __|  _ \    _ \  
    _ \    |   |  |       |   |  __|      |    __|    |        |   |   |  |   | 
   ___ \   ___/   |       |   |  |        |    |      |        |   |   |  __ <  
 _/    _\ _|    ___|     ____/  _____|   _|   _____| \____|   _|  \___/  _| \_\ 
                                       
                                        https://github.com/brinhosa/apidetector                                                                                                              
"""

sensitive_headers = ['Authorization', 'Set-Cookie', 'X-API-Key', 'X-Auth-Token']
sensitive_json_keys = ['password', 'token', 'secret', 'key', 'access']
error_indicators = ['Exception', 'Traceback', 'SQL', 'NullPointer', 'stack trace', 'Cannot read property']

swagger_patterns = ['/swagger-ui', '/api-docs', '/openapi', '/swagger.', '/swagger-resources']

additional_endpoints = [
    '/auth/login', '/auth/token', '/auth/refresh', '/auth/logout', '/users',
    '/users/me', '/users/reset-password', '/admin', '/admin/config', '/internal',
    '/settings', '/debug', '/dev', '/actuator', '/api/token', '/api/token/refresh',
    '/api/token/validate', '/v1/token', '/v1/login', '/session', '/signin', '/signup'
]

def generate_random_string(length=21):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def test_endpoint(url, error_content, verbose, user_agent, poc_already_generated=False):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=30, allow_redirects=False)

        if response.status_code == 200 and "Page Not Found".lower() not in response.text.lower():
            similarity = difflib.SequenceMatcher(None, error_content, response.text).ratio()
            if similarity < 0.90:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc

                if '/swagger-ui/index.html' in url and not poc_already_generated:
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    poc_path = os.path.join(current_dir, 'pocgenerator.py')
                    endpoint_url = url + "?configUrl=https://raw.githubusercontent.com/brinhosa/payloads/master/testswagger.json"

                    env = os.environ.copy()
                    env['DOMAIN'] = domain
                    env['GENERATE_POC'] = 'true'

                    result = subprocess.run(['python3', poc_path, endpoint_url], env=env, capture_output=True, text=True)
                    if 'Screenshot saved' in result.stdout:
                        os.environ[f'SCREENSHOT_CREATED_{domain.replace('.', '_')}'] = 'true'

                # OWASP API Top 10 Checks
                for header, value in response.headers.items():
                    if any(h.lower() in header.lower() for h in sensitive_headers):
                        print(f"[!] Sensitive header in {url}: {header}: {value}")
                    if "eyJ" in value and "." in value:
                        print(f"[!] Possible JWT token in header from {url}: {value}")

                if "eyJ" in response.text and "." in response.text:
                    print(f"[!] Possible JWT token in body from {url}")

                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        print(f"[!] Verbose error in {url}: {indicator}")

                try:
                    data = response.json()
                    for key in sensitive_json_keys:
                        if key in data:
                            print(f"[!] Sensitive JSON key '{key}' found in {url}")
                except Exception:
                    pass

                if any(s in url for s in ['/admin', '/me', '/settings']):
                    print(f"[!] Potential unauthorized access to sensitive endpoint: {url}")

                return url
    except requests.RequestException:
        pass
    return None

def test_subdomain_endpoints(subdomain, endpoints, mixed_mode, verbose, user_agent):
    protocols = ['https://', 'http://'] if mixed_mode else ['https://']
    valid_urls, error_content = [], ""
    random_path = generate_random_string()

    for protocol in protocols:
        error_url = f"{protocol}{subdomain}/{random_path}"
        try:
            err_resp = requests.get(error_url, headers={'User-Agent': user_agent}, timeout=15)
            if err_resp.status_code == 404 or "Page Not Found".lower() in err_resp.text.lower():
                error_content = err_resp.text
                break
        except requests.RequestException:
            pass

    try:
        r1 = requests.get(f"https://{subdomain}/api/swagger/v3/api-docs", timeout=15)
        r2 = requests.get(f"https://{subdomain}/api/swagger/v2/api-docs", timeout=15)
        if r1.status_code == 200 and r2.status_code == 200:
            sim = difflib.SequenceMatcher(None, r1.text, r2.text).ratio()
            if sim > 0.70:
                print(f"{subdomain} not valid to test. Similarity: {sim}")
                return []
    except:
        pass

    poc_generated = False
    for protocol in protocols:
        for endpoint in endpoints:
            url = f"{protocol}{subdomain}{endpoint}"
            result = test_endpoint(url, error_content, verbose, user_agent, poc_generated)
            if result:
                valid_urls.append(result)
                if any(pattern in url for pattern in swagger_patterns):
                    poc_generated = True
                if verbose:
                    print(f"[+] Found: {url}")
    return valid_urls

def main(domain, input_file, output_file, num_threads, endpoints, mixed_mode, verbose, user_agent):
    subdomains = [domain] if domain else []
    if not domain:
        with open(input_file, 'r') as file:
            subdomains.extend(line.strip() for line in file)

    all_valid_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(test_subdomain_endpoints, sub, endpoints, mixed_mode, verbose, user_agent) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            all_valid_urls.extend(future.result())

    if all_valid_urls:
        if output_file:
            with open(output_file, 'w') as file:
                for url in sorted(set(all_valid_urls)):
                    file.write(url + '\n')
            print(f"[✔] Completed. Results saved in {output_file}")
        else:
            print("[✔] Results:")
            for url in sorted(set(all_valid_urls)):
                print(url)
    else:
        print("[x] No exposed URLs found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APIDetector Extended - OWASP API Top 10 Aware" + ascii_art,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--domain", help="Single domain to test")
    parser.add_argument("-i", "--input", help="Input file with subdomains")
    parser.add_argument("-o", "--output", help="File to write results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Thread count")
    parser.add_argument("-m", "--mixed-mode", action='store_true', help="Test HTTP and HTTPS")
    parser.add_argument("-q", "--quiet", action='store_true', help="Quiet mode")
    parser.add_argument("-ua", "--user-agent", default="APIDetector", help="User-Agent string")

    args = parser.parse_args()
    verbose = not args.quiet

    default_endpoints = [
        '/swagger-ui.html', '/openapi.json', '/v2/api-docs', '/v3/api-docs', '/swagger.json',
        '/api-docs', '/docs', '/swagger-ui/', '/swagger-ui/index.html', '/swagger-resources'
    ]
    all_endpoints = list(set(default_endpoints + additional_endpoints))

    if not args.domain and not args.input:
        parser.error("You must provide a --domain or --input file")

    main(args.domain, args.input, args.output, args.threads, all_endpoints, args.mixed_mode, verbose, args.user_agent)
