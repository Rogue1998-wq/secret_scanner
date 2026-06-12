
import re
import sys
import os
import requests
from urllib.parse import urlparse

# Define regex patterns for common secrets
# These are basic examples; a real scanner would have many more and more complex patterns
SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([a-zA-Z0-9/+=]{40})['\"]",
    "Google Cloud API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
    "Generic API Key": r"(?i)(api_key|apikey|secret|token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
    "JSON Web Token (JWT)": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (OPENSSH) private key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Facebook Oauth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "Twitter Oauth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Picatic API Key": r"sk_[live|test]_[0-9a-z]{32}",
    "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal Classic API Key": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Firebase Cloud Messaging": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Braintree Client Token": r"client_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailjet API Key": r"key-[0-9a-z]{32}",
    "Datadog API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "New Relic API Key": r"[0-9a-f]{40}",
    "Sentry API Key": r"[0-9a-f]{40}",
    "Loggly API Key": r"[0-9a-f]{40}",
    "Raygun API Key": r"[0-9a-f]{40}",
    "Papertrail API Key": r"[0-9a-f]{40}",
    "Rollbar API Key": r"[0-9a-f]{40}",
    "Bugsnag API Key": r"[0-9a-f]{40}",
    "Airbrake API Key": r"[0-9a-f]{40}",
    "Honeybadger API Key": r"[0-9a-f]{40}",
    "Sentry API Key": r"[0-9a-f]{40}",
    "Logentries API Key": r"[0-9a-f]{40}",
    "Splunk API Key": r"[0-9a-f]{40}",
    "Sumo Logic API Key": r"[0-9a-f]{40}",
    "Mixpanel API Key": r"[0-9a-f]{40}",
    "Segment API Key": r"[0-9a-f]{40}",
    "Amplitude API Key": r"[0-9a-f]{40}",
    "Heap API Key": r"[0-9a-f]{40}",
    "Kissmetrics API Key": r"[0-9a-f]{40}",
    "Localytics API Key": r"[0-9a-f]{40}",
    "Google Analytics API Key": r"[0-9a-f]{40}",
    "Adobe Analytics API Key": r"[0-9a-f]{40}",
    "Piwik API Key": r"[0-9a-f]{40}",
    "Flurry API Key": r"[0-9a-f]{40}",
    "Appboy API Key": r"[0-9a-f]{40}",
    "Countly API Key": r"[0-9a-f]{40}",
    "Fabric API Key": r"[0-9a-f]{40}",
    "Adjust API Key": r"[0-9a-f]{40}",
    "Kochava API Key": r"[0-9a-f]{40}",
    "Apsalar API Key": r"[0-9a-f]{40}",
    "Upsight API Key": r"[0-9a-f]{40}",
    "Tune API Key": r"[0-9a-f]{40}",
    "AppsFlyer API Key": r"[0-9a-f]{40}",
    "Branch API Key": r"[0-9a-f]{40}",
    "Tenjin API Key": r"[0-9a-f]{40}",
    "Singular API Key": r"[0-9a-f]{40}",
    "Kochava API Key": r"[0-9a-f]{40}",
    "Apsalar API Key": r"[0-9a-f]{40}",
    "Upsight API Key": r"[0-9a-f]{40}",
    "Tune API Key": r"[0-9a-f]{40}",
    "AppsFlyer API Key": r"[0-9a-f]{40}",
    "Branch API Key": r"[0-9a-f]{40}",
    "Tenjin API Key": r"[0-9a-f]{40}",
    "Singular API Key": r"[0-9a-f]{40}"
}

def scan_content(content, source_name):
    """Scans the given content for secrets using regex patterns."""
    findings = []
    for secret_name, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            # Extract a snippet of context around the match
            start = max(0, match.start() - 20)
            end = min(len(content), match.end() + 20)
            context = content[start:end].replace('\n', ' ')
            
            findings.append({
                "source": source_name,
                "type": secret_name,
                "match": match.group(0),
                "context": context
            })
    return findings

def scan_file(file_path):
    """Reads a local file and scans it for secrets."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            return scan_content(content, file_path)
    except Exception as e:
        print(f"[-] Error reading file {file_path}: {e}")
        return []

def scan_url(url):
    """Fetches a remote URL and scans its content for secrets."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return scan_content(response.text, url)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching URL {url}: {e}")
        return []

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 js_secret_scanner.py <file_path_or_url>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Scanning target: {target}\n")

    findings = []
    
    # Determine if target is a URL or a local file
    parsed_url = urlparse(target)
    if parsed_url.scheme in ['http', 'https']:
        findings = scan_url(target)
    elif os.path.isfile(target):
        findings = scan_file(target)
    elif os.path.isdir(target):
        # If it's a directory, scan all .js files within it
        for root, _, files in os.walk(target):
            for file in files:
                if file.endswith('.js'):
                    file_path = os.path.join(root, file)
                    findings.extend(scan_file(file_path))
    else:
        print("[-] Invalid target. Must be a valid URL, file path, or directory.")
        sys.exit(1)

    if findings:
        print(f"[!] Found {len(findings)} potential secret(s):\n")
        for finding in findings:
            print(f"---")
            print(f"Source : {finding['source']}")
            print(f"Type   : {finding['type']}")
            print(f"Match  : {finding['match']}")
            print(f"Context: ...{finding['context']}...")
        print(f"---\n")
    else:
        print("[+] No secrets found.")

if __name__ == "__main__":
    main()
