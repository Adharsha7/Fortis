import requests
import re

# Common API key patterns
PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "OpenAI Key": r'sk-[a-zA-Z0-9]{20,}',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase URL": r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
    "Generic API Key": r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}'
}

def check_cloud_key_exposure(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)
        content = response.text

        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)

            if matches:
                for match in matches:
                    findings.append({
                        "type": "Cloud / API Key Exposure",
                        "severity": "High",
                        "service": name,
                        "detected_value": match[:6] + "********",
                        "description": f"Possible exposed {name} detected in source code."
                    })

    except requests.exceptions.RequestException as e:
       print("Connection error:", e)
    return findings


# 🔥 Execution block (for testing module independently)
if __name__ == "__main__":
    target = input("Enter URL: ")

    results = check_cloud_key_exposure(target)

    if results:
        print("\nCloud / AI Key Exposure Found:\n")
        for r in results:
            print(r)
    else:
        print("\nNo cloud/API key exposure detected.")