import requests

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/database.sql",
    "/config.bak",
    "/.htaccess",
    "/.DS_Store"
]

SENSITIVE_KEYWORDS = [
    "DB_PASSWORD",
    "API_KEY",
    "SECRET",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "BEGIN RSA PRIVATE KEY"
]

def check_sensitive_files(url):
    findings = []

    for path in SENSITIVE_PATHS:
        full_url = url.rstrip("/") + path

        try:
            response = requests.get(full_url, timeout=5, allow_redirects=True)

            # Only consider real exposure
            if response.status_code == 200 and len(response.text) > 10:

                severity = "Medium"
                detected_keywords = []

                # Check content for sensitive keywords
                for keyword in SENSITIVE_KEYWORDS:
                    if keyword in response.text:
                        detected_keywords.append(keyword)

                # Increase severity if secrets detected
                if detected_keywords:
                    severity = "High"

                findings.append({
                    "type": "Sensitive File Exposure",
                    "url": full_url,
                    "severity": severity,
                    "keywords_found": detected_keywords,
                    "description": "Sensitive file is publicly accessible."
                })

        except requests.exceptions.RequestException:
            continue

    return findings
if __name__ == "__main__":
    target = input("Enter URL: ")
    results = check_sensitive_files(target)

    if results:
        print("\nSensitive files found:\n")
        for r in results:
            print(r)
    else:
        print("No sensitive files detected.")