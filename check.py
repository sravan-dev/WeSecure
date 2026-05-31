"""
WeSecure - WordPress Security Checker
Author: Sravan M
Purpose: Test YOUR OWN WordPress site for weak credentials.

WARNING: Only use on sites you own. Unauthorized access is illegal.
"""

import requests
import sys
import time
from urllib.parse import urljoin

# Common weak passwords to test against
COMMON_PASSWORDS = [
    'password', 'password123', 'admin', 'admin123', 'admin1234',
    'admin12345', 'admin123456', '123456', '12345678', '123456789',
    'qwerty', 'qwerty123', 'letmein', 'welcome', 'monkey',
    'dragon', 'master', 'login', 'abc123', 'wordpress',
    'wp-admin', 'pass123', 'changeme', 'test', 'test123',
    'root', 'toor', 'administrator', 'passwd', 'pass',
    '1234567890', 'iloveyou', 'trustno1', 'sunshine', 'princess',
    'football', 'shadow', 'superman', 'michael', 'access',
    'hello', 'charlie', 'donald', '!@#$%^&*', 'aa123456',
    'password1', 'password12', 'passw0rd', 'p@ssw0rd', 'p@ssword',
]


def banner():
    print("""
╔══════════════════════════════════════════════╗
║         WeSecure - WP Security Checker       ║
║         Author: Sravan M                     ║
║         Use only on YOUR OWN sites!          ║
╚══════════════════════════════════════════════╝
    """)


def enumerate_users(target_url):
    """Detect WordPress usernames via REST API and author enumeration."""
    print("[*] Enumerating users...")
    users_found = []

    # Method 1: REST API
    print("    [>] Trying REST API /wp-json/wp/v2/users ...")
    try:
        api_url = urljoin(target_url, '/wp-json/wp/v2/users')
        resp = requests.get(api_url, timeout=10, verify=True)
        if resp.status_code == 200:
            data = resp.json()
            for user in data:
                username = user.get('slug', '')
                if username and username not in users_found:
                    users_found.append(username)
                    print(f"    [+] Found user (REST API): {username}")
        else:
            print(f"    [-] REST API blocked (status {resp.status_code}) - Good!")
    except Exception as e:
        print(f"    [-] REST API error: {e}")

    # Method 2: Author ID enumeration
    print("    [>] Trying author ID enumeration (?author=N) ...")
    for author_id in range(1, 11):
        try:
            url = urljoin(target_url, f'/?author={author_id}')
            resp = requests.get(url, timeout=10, allow_redirects=True, verify=True)
            # Check if redirected to /author/username/
            if '/author/' in resp.url:
                username = resp.url.rstrip('/').split('/author/')[-1]
                if username and username not in users_found:
                    users_found.append(username)
                    print(f"    [+] Found user (author enum): {username}")
        except Exception:
            pass

    # Method 3: wp-json oembed
    print("    [>] Trying oEmbed endpoint ...")
    try:
        oembed_url = urljoin(target_url, '/wp-json/oembed/1.0/embed?url=' + target_url)
        resp = requests.get(oembed_url, timeout=10, verify=True)
        if resp.status_code == 200:
            data = resp.json()
            author = data.get('author_name', '')
            if author and author not in users_found:
                users_found.append(author)
                print(f"    [+] Found user (oEmbed): {author}")
    except Exception:
        pass

    if not users_found:
        print("    [-] No users found. Site is well-protected against enumeration!")
    else:
        print(f"\n[*] Total users found: {len(users_found)}")
        for u in users_found:
            print(f"    - {u}")

    return users_found


def check_xmlrpc(target_url):
    """Check if XML-RPC is enabled (used for brute force amplification)."""
    print("\n[*] Checking XML-RPC status...")
    try:
        xmlrpc_url = urljoin(target_url, '/xmlrpc.php')
        # Send a simple method call
        payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>"""
        resp = requests.post(xmlrpc_url, data=payload, timeout=10, verify=True)
        if resp.status_code == 200 and 'methodResponse' in resp.text:
            print("    [!] XML-RPC is ENABLED - vulnerable to brute force amplification!")
            return True
        else:
            print("    [+] XML-RPC is disabled or blocked. Good!")
            return False
    except Exception:
        print("    [+] XML-RPC not accessible.")
        return False


def brute_force_login(target_url, username, passwords=None, delay=1):
    """Attempt login with common passwords via wp-login.php."""
    if passwords is None:
        passwords = COMMON_PASSWORDS

    # Also add username-based guesses
    username_passwords = [
        username,
        username + '123',
        username + '1234',
        username + '12345',
        username + '123456',
        username + '@123',
        username + '@1234',
        username + '!',
        username + '!123',
        username.capitalize() + '123',
        username.capitalize() + '@123',
    ]
    passwords = username_passwords + passwords

    login_url = urljoin(target_url, '/wp-login.php')
    print(f"\n[*] Testing {len(passwords)} passwords for user: {username}")
    print(f"    Target: {login_url}")
    print(f"    Delay between attempts: {delay}s")
    print("-" * 50)

    session = requests.Session()

    # Get login page first (for cookies)
    try:
        session.get(login_url, timeout=10, verify=True)
    except Exception as e:
        print(f"    [!] Cannot reach login page: {e}")
        return None

    for i, password in enumerate(passwords, 1):
        try:
            data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': urljoin(target_url, '/wp-admin/'),
                'testcookie': '1',
            }

            resp = session.post(
                login_url,
                data=data,
                allow_redirects=False,
                timeout=10,
                verify=True,
            )

            # Check for successful login (302 redirect to wp-admin)
            if resp.status_code == 302 and 'wp-admin' in resp.headers.get('Location', ''):
                print(f"\n    [!!!] PASSWORD FOUND: {username}:{password}")
                print(f"    [!!!] Your site is VULNERABLE! Change this password immediately!")
                return password

            # Check if locked out
            if 'too many' in resp.text.lower() or resp.status_code == 429:
                print(f"\n    [+] Lockout detected after {i} attempts. Brute force protection is working!")
                return 'LOCKED_OUT'

            # Progress indicator
            if i % 10 == 0:
                print(f"    [{i}/{len(passwords)}] tested... no match yet")

            time.sleep(delay)

        except requests.exceptions.Timeout:
            print(f"    [!] Timeout on attempt {i}, continuing...")
            continue
        except Exception as e:
            print(f"    [!] Error: {e}")
            continue

    print(f"\n    [+] All {len(passwords)} passwords tested. None matched.")
    print("    [+] Password appears to be strong against common attacks.")
    return None


def check_security_headers(target_url):
    """Check for important security headers."""
    print("\n[*] Checking security headers...")
    try:
        resp = requests.get(target_url, timeout=10, verify=True)
        headers = resp.headers

        checks = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1',
            'Content-Security-Policy': None,
            'Strict-Transport-Security': None,
            'Referrer-Policy': None,
            'Permissions-Policy': None,
        }

        for header, expected in checks.items():
            value = headers.get(header, '')
            if value:
                print(f"    [+] {header}: {value[:60]}")
            else:
                print(f"    [!] {header}: MISSING")

        # Check for info leakage
        print("\n[*] Checking info leakage headers...")
        leaky = ['X-Powered-By', 'Server']
        for header in leaky:
            value = headers.get(header, '')
            if value and value != 'WeSecure':
                print(f"    [!] {header}: {value} (EXPOSED - should be hidden)")
            else:
                print(f"    [+] {header}: Hidden or removed")

    except Exception as e:
        print(f"    [!] Error: {e}")


def generate_report(target_url, users, xmlrpc_enabled, login_result):
    """Print final security report."""
    print("\n")
    print("=" * 55)
    print("           WESECURE SECURITY REPORT")
    print("=" * 55)
    print(f"  Target: {target_url}")
    print(f"  Date:   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 55)

    issues = []

    if users:
        issues.append(f"Username(s) exposed: {', '.join(users)}")
    if xmlrpc_enabled:
        issues.append("XML-RPC enabled (brute force amplification possible)")
    if login_result and login_result != 'LOCKED_OUT':
        issues.append(f"CRITICAL: Weak password found!")
    if login_result != 'LOCKED_OUT':
        issues.append("No brute force lockout detected")

    if issues:
        print("\n  ISSUES FOUND:")
        for i, issue in enumerate(issues, 1):
            print(f"    {i}. {issue}")
    else:
        print("\n  No critical issues found!")

    print("\n  RECOMMENDATIONS:")
    if users:
        print("    - Install WeSecure plugin to block REST API user enumeration")
    if xmlrpc_enabled:
        print("    - Disable XML-RPC (add to .htaccess or use WeSecure)")
    if login_result and login_result != 'LOCKED_OUT':
        print("    - IMMEDIATELY change password to 16+ char random string")
        print("    - Enable 2FA authentication")
    if login_result != 'LOCKED_OUT':
        print("    - Enable login brute force protection (WeSecure plugin)")
    print("    - Keep WordPress, themes, and plugins updated")
    print("    - Use WeSecure plugin for ongoing protection")

    print("\n" + "=" * 55)


def main():
    banner()

    if len(sys.argv) < 2:
        target_url = input("[?] Enter your WordPress site URL: ").strip()
    else:
        target_url = sys.argv[1]

    # Normalize URL
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url
    target_url = target_url.rstrip('/')

    print(f"\n[*] Target: {target_url}")
    print("[*] Starting security check...\n")

    # Confirm ownership
    confirm = input("[?] Do you own this website? (yes/no): ").strip().lower()
    if confirm not in ('yes', 'y'):
        print("[!] Aborting. Only test sites you own.")
        sys.exit(1)

    # Step 1: Enumerate users
    users = enumerate_users(target_url)

    # Step 2: Check XML-RPC
    xmlrpc_enabled = check_xmlrpc(target_url)

    # Step 3: Check security headers
    check_security_headers(target_url)

    # Step 4: Brute force test
    login_result = None
    if users:
        print(f"\n[?] Test login strength for discovered users?")
        test_login = input("    (yes/no): ").strip().lower()
        if test_login in ('yes', 'y'):
            for username in users:
                login_result = brute_force_login(target_url, username, delay=1)
                if login_result and login_result != 'LOCKED_OUT':
                    break
    else:
        # Try with common admin usernames
        print("\n[*] No users found via enumeration. Testing common usernames...")
        common_users = ['admin', 'administrator', 'wp-admin']
        test_login = input("[?] Test login with common usernames? (yes/no): ").strip().lower()
        if test_login in ('yes', 'y'):
            for username in common_users:
                login_result = brute_force_login(target_url, username, delay=1)
                if login_result and login_result != 'LOCKED_OUT':
                    break

    # Final Report
    generate_report(target_url, users, xmlrpc_enabled, login_result)


if __name__ == '__main__':
    main()
