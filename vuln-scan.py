import argparse
import requests
import os
from concurrent.futures import ThreadPoolExecutor

def get_subdomains(target):
    subdomains = []
    # Example using crt.sh (Certificate Transparency logs)
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            json_response = response.json()
            for cert in json_response:
                subdomain = cert['name_value']
                if '\n' in subdomain:
                    subdomains.extend(subdomain.split('\n'))
                else:
                    subdomains.append(subdomain)
    except Exception as e:
        print(f"Error fetching subdomains: {e}")
    return list(set(subdomains))  # Remove duplicates

def check_status(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        return subdomain, response.status_code
    except requests.exceptions.RequestException:
        return subdomain, None

def categorize_subdomains(subdomains, target):
    os.makedirs(target, exist_ok=True)
    status_files = {
        404: open(os.path.join(target, '404.txt'), 'w'),
        403: open(os.path.join(target, '403.txt'), 'w'),
        200: open(os.path.join(target, '200.txt'), 'w')
    }
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_status, subdomain) for subdomain in subdomains]
        for future in futures:
            subdomain, status_code = future.result()
            if status_code in status_files:
                status_files[status_code].write(subdomain + '\n')
            else:
                print(f"Subdomain {subdomain} returned status code {status_code}")

    for file in status_files.values():
        file.close()

def check_subdomain_takeover(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        if 'NoSuchBucket' in response.text or 'There isn't a GitHub Pages site here' in response.text:
            return subdomain
    except requests.exceptions.RequestException:
        pass
    return None

def check_forbidden_bypass(subdomain):
    try:
        methods = ['HEAD', 'OPTIONS', 'PUT', 'DELETE']
        for method in methods:
            response = requests.request(method, f"http://{subdomain}", timeout=5)
            if response.status_code == 200:
                return subdomain
    except requests.exceptions.RequestException:
        pass
    return None

def analyze_vulnerabilities(target):
    takeover_vulns = []
    forbidden_bypass_vulns = []

    with open(os.path.join(target, '404.txt'), 'r') as file:
        subdomains = file.read().splitlines()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain_takeover, subdomain) for subdomain in subdomains]
            for future in futures:
                result = future.result()
                if result:
                    takeover_vulns.append(result)

    with open(os.path.join(target, '403.txt'), 'r') as file:
        subdomains = file.read().splitlines()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_forbidden_bypass, subdomain) for subdomain in subdomains]
            for future in futures:
                result = future.result()
                if result:
                    forbidden_bypass_vulns.append(result)

    with open(os.path.join(target, 'takeover_vulns.txt'), 'w') as file:
        for vuln in takeover_vulns:
            file.write(vuln + '\n')

    with open(os.path.join(target, 'forbidden_bypass_vulns.txt'), 'w') as file:
        for vuln in forbidden_bypass_vulns:
            file.write(vuln + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subdomain Enumeration and Vulnerability Analysis Tool')
    parser.add_argument('target', type=str, help='Target domain')
    args = parser.parse_args()

    target = args.target
    print(f'Gathering subdomains for {target}...')
    subdomains = get_subdomains(target)
    print(f'Found {len(subdomains)} subdomains.')

    print('Checking status codes of subdomains...')
    categorize_subdomains(subdomains, target)

    print('Analyzing vulnerabilities...')
    analyze_vulnerabilities(target)
    print('Vulnerability analysis complete.')
