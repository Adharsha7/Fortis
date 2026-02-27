import requests
import re
import base64
import json

# Regex pattern to detect JWT tokens
JWT_REGEX = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'


def decode_base64(data):
    """Decode base64 safely (adds padding if needed)"""
    try:
        padding = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode('utf-8')
    except:
        return None


def check_jwt_security(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)
        content = response.text

        # 🔎 1️⃣ Check for localStorage usage
        if "localStorage.setItem" in content:
            findings.append({
                "type": "Insecure JWT Storage",
                "severity": "Medium",
                "description": "JWT may be stored in localStorage (XSS risk)."
            })

        # 🔎 2️⃣ Detect JWT tokens in page source
        jwt_matches = re.findall(JWT_REGEX, content)

        for token in jwt_matches:
            parts = token.split(".")

            if len(parts) == 3:
                header_encoded = parts[0]
                payload_encoded = parts[1]

                header_decoded = decode_base64(header_encoded)
                payload_decoded = decode_base64(payload_encoded)

                # 🔥 Check algorithm weakness
                if header_decoded:
                    try:
                        header_json = json.loads(header_decoded)

                        if header_json.get("alg") == "none":
                            findings.append({
                                "type": "JWT Algorithm Misconfiguration",
                                "severity": "High",
                                "description": "JWT uses 'none' algorithm (no signature verification)."
                            })
                    except:
                        pass

                # 🔥 Check missing expiration
                if payload_decoded:
                    try:
                        payload_json = json.loads(payload_decoded)

                        if "exp" not in payload_json:
                            findings.append({
                                "type": "JWT Missing Expiry",
                                "severity": "Medium",
                                "description": "JWT token does not contain expiration (exp) claim."
                            })
                    except:
                        pass

    except requests.exceptions.RequestException:
        print("Error connecting to target.")

    return findings


# 🔥 Execution Block
if __name__ == "__main__":
    target = input("Enter URL: ")

    results = check_jwt_security(target)

    if results:
        print("\nJWT Issues Found:\n")
        for r in results:
            print(r)
    else:
        print("\nNo JWT vulnerabilities detected.")