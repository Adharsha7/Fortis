import requests
import threading
from urllib.parse import urljoin
from datetime import datetime

# Common admin/login panel paths
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/login.php",
    "/administrator", "/administrator/", "/administrator/login",
    "/login", "/login.php", "/login.html", "/login/",
    "/signin", "/signin.php", "/sign-in",
    "/user/login", "/users/login", "/account/login",
    "/auth", "/auth/login", "/authenticate",
    "/panel", "/panel/", "/cpanel", "/control",
    "/dashboard", "/dashboard/login",
    "/wp-admin", "/wp-admin/", "/wp-login.php",        
    "/wp-admin/admin-ajax.php",
    "/joomla/administrator", "/administrator/index.php", 
    "/drupal/admin", "/user",                           
    "/magento/admin", "/index.php/admin",               
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin",  
    "/webmail", "/roundcube", "/squirrelmail",           
    "/manager/html", "/host-manager/html",              
    "/admin.php", "/admin.html", "/admin.asp",
    "/admin/index.php", "/admin/index.html",
    "/backend", "/backend/login", "/backend/admin",
    "/secure", "/secure/login",
    "/portal", "/portal/login",
    "/staff", "/staff/login",
    "/moderator", "/moderator/login",
    "/webadmin", "/siteadmin",
    "/adminpanel", "/admin_panel",
]

# Keywords that indicate a login/admin page
LOGIN_KEYWORDS = [
    "login", "log in", "sign in", "signin",
    "username", "password", "admin", "administrator",
    "email", "passwd", "dashboard", "welcome back",
    "enter your", "forgot password", "remember me",
]

FOUND = []
LOCK = threading.Lock()

def check_path(base_url, path, timeout=5):
    url = urljoin(base_url, path)
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}
        )

        status = response.status_code
        content = response.text.lower()

        # Check for success or interesting status codes
        if status in [200, 401, 403]:
            is_login = any(keyword in content for keyword in LOGIN_KEYWORDS)
            final_url = response.url  # After redirects

            with LOCK:
                result = {
                    "url": final_url,
                    "original_path": path,
                    "status": status,
                    "likely_login": is_login,
                    "content_length": len(response.text),
                }

                if status == 200 and is_login:
                    result["risk"] = "HIGH - Open login panel found"
                elif status == 401:
                    result["risk"] = "MEDIUM - Auth required (panel exists)"
                elif status == 403:
                    result["risk"] = "LOW - Forbidden (panel exists but blocked)"
                elif status == 200:
                    result["risk"] = "INFO - Page exists (no login detected)"
                else:
                    return

                FOUND.append(result)
                print(f"  [{status}] {final_url} → {result['risk']}")

    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except Exception as e:
        pass


def scan_admin_panels(target_url, threads=10, timeout=5):
    # Normalize URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    print(f"\n{'='*60}")
    print(f"  Admin/Login Panel Scanner")
    print(f"{'='*60}")
    print(f"  Target  : {target_url}")
    print(f"  Paths   : {len(ADMIN_PATHS)}")
    print(f"  Threads : {threads}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    thread_list = []
    semaphore = threading.Semaphore(threads)

    def worker(path):
        with semaphore:
            check_path(target_url, path, timeout)

    for path in ADMIN_PATHS:
        t = threading.Thread(target=worker, args=(path,))
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()

    # Summary
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — {len(FOUND)} finding(s)")
    print(f"{'='*60}")

    if FOUND:
        high   = [r for r in FOUND if "HIGH"   in r["risk"]]
        medium = [r for r in FOUND if "MEDIUM" in r["risk"]]
        low    = [r for r in FOUND if "LOW"    in r["risk"]]
        info   = [r for r in FOUND if "INFO"   in r["risk"]]

        print(f"   HIGH   : {len(high)}")
        print(f"   MEDIUM : {len(medium)}")
        print(f"   LOW    : {len(low)}")
        print(f"   INFO   : {len(info)}")
        print()

        for r in sorted(FOUND, key=lambda x: x["status"]):
            print(f"  • [{r['status']}] {r['url']}")
            print(f"         Risk   : {r['risk']}")
            print(f"         Login? : {'Yes' if r['likely_login'] else 'No'}")
            print(f"         Size   : {r['content_length']} bytes\n")
    else:
        print("  No admin/login panels detected.")

    return FOUND


# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target URL: ").strip()
    results = scan_admin_panels(target)