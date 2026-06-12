# JS Secret Scanner

This Python script is designed to help identify potentially leaked API keys, tokens, and other sensitive credentials within JavaScript files or web pages. It uses a set of regular expressions to scan content for patterns commonly associated with secrets, making it a valuable tool for security audits, bug bounty hunting, and ensuring that sensitive information is not inadvertently exposed.

## Features

*   Scans local JavaScript files or entire directories for secrets.
*   Fetches and scans remote JavaScript files from URLs.
*   Utilizes a comprehensive list of regex patterns for various secret types (AWS, Google Cloud, Stripe, GitHub, JWTs, private keys, etc.).
*   Provides detailed output including the type of secret, the matched string, and surrounding context.

## Installation

1.  **Clone the repository** (or download the `js_secret_scanner.py` file):
    ```bash
    git clone https://github.com/your-username/js-secret-scanner.git
    cd js-secret-scanner
    ```

2.  **Install dependencies**:
    This script requires the `requests` library. You can install it using pip:
    ```bash
    pip install requests
    ```

## Usage

Run the script from your terminal, providing the target (file path, directory path, or URL) as an argument:

```bash
python3 js_secret_scanner.py <target>
```

**Examples**:

*   **Scan a local JavaScript file**:
    ```bash
    python3 js_secret_scanner.py /path/to/your/script.js
    ```

*   **Scan a directory containing JavaScript files**:
    ```bash
    python3 js_secret_scanner.py /path/to/your/js_folder/
    ```

*   **Scan a remote JavaScript file from a URL**:
    ```bash
    python3 js_secret_scanner.py https://example.com/assets/app.js
    ```

## How it Works

The `js_secret_scanner.py` script takes a target as input. It determines if the target is a local file, a directory, or a URL. 

*   If it's a **local file**, it reads the file's content.
*   If it's a **directory**, it recursively finds and reads all `.js` files within it.
*   If it's a **URL**, it makes an HTTP GET request to fetch the content of the remote file.

Once the content is obtained, the script applies a series of regular expressions (defined in `SECRET_PATTERNS`) to find matches. For each match, it reports the type of secret, the matched string, and a snippet of the surrounding code for context.

## Customizing Secret Patterns

You can extend or modify the `SECRET_PATTERNS` dictionary in the `js_secret_scanner.py` file to include additional regex patterns for secrets you want to detect. Each entry in the dictionary should have:

*   A descriptive name for the secret type (e.g., "New API Key").
*   A regular expression string that matches the pattern of the secret.

## Disclaimer

This tool is intended for educational and legitimate security auditing purposes only. It is not foolproof and may produce false positives or miss certain types of secrets. Always verify findings manually. Do not use this tool for illegal activities or without proper authorization. The author is not responsible for any misuse of this tool.
