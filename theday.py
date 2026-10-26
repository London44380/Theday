#!/usr/bin/env python3
"""
THEDAY - authorized web recon / misconfiguration scanner.

For use ONLY against targets you own or are explicitly authorized to test
(pentest engagement, CTF, bug bounty in scope). Unauthorized scanning of
third-party systems may be illegal in your jurisdiction.
"""

import argparse
import contextlib
import ipaddress
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
REDIRECT_LABELS = {
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
}

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = r"""
 _____ _   _ _____ ____    _ __   __
|_   _| | | | ____|  _ \  / \\ \ / /
  | | | |_| |  _| | | | |/ _ \\ V /
  | | |  _  | |___| |_| / ___ \| |
  |_| |_| |_|_____|____/_/   \_\_|
"""

SENSITIVE_PATHS = [
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.bak",
    "wp-config.php.bak",
    "config.php.bak",
    "backup.zip",
    "backup.tar.gz",
    ".DS_Store",
    ".svn/entries",
    "docker-compose.yml",
    "id_rsa",
    "phpinfo.php",
    "server-status",
    "admin/",
    "wp-admin/",
    "wp-login.php",
    ".well-known/security.txt",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

VERSION_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def clean(s) -> str:
    """Neutralise control characters (ANSI escapes...) from server-controlled
    data (headers, cookie names, redirect locations...) before it reaches
    the terminal."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(s))


def print_banner():
    print(f"{RED}{BOLD}{BANNER}{RESET}")
    print(f"{RED}{BOLD}            THEDAY{RESET}")
    print(f"{RED}        Web Recon / Misconfig Scanner{RESET}\n")


def normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


@contextlib.contextmanager
def dns_override(hostname: str, ip: str):
    """Force DNS resolution of `hostname` to `ip` for the duration of the scan,
    like `curl --resolve`. Lets you reach an origin server directly (bypassing
    a CDN/WAF's DNS record) while Host header, TLS SNI and cert verification
    all still use the real hostname, exactly as a normal browser would."""
    if not hostname or not ip:
        yield
        return

    original_getaddrinfo = socket.getaddrinfo

    def patched_getaddrinfo(host, *args, **kwargs):
        if host == hostname:
            host = ip
        return original_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = patched_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


def check_security_headers(session: requests.Session, base_url: str) -> list:
    findings = []
    try:
        resp = session.get(base_url, timeout=10, allow_redirects=True)
    except RequestException as exc:
        findings.append(("error", f"Could not fetch {base_url}: {exc}"))
        return findings

    for header in SECURITY_HEADERS:
        if header not in resp.headers:
            findings.append(("missing_header", header))

    for header in VERSION_DISCLOSURE_HEADERS:
        value = resp.headers.get(header)
        if value:
            findings.append(("version_disclosure", f"{header}: {value}"))

    for cookie in resp.cookies:
        flags = []
        if not cookie.secure:
            flags.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            flags.append("HttpOnly")
        if flags:
            findings.append(("cookie_flags", f"{cookie.name} missing: {', '.join(flags)}"))

    return findings


def safe_filename(url: str) -> str:
    path = urlparse(url).path.strip("/") or "index"
    return re.sub(r"[^A-Za-z0-9._-]", "_", path)


def download_file(session: requests.Session, url: str, download_dir: str, timeout: int = 8):
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
    except RequestException as exc:
        return None, str(exc)
    if resp.status_code >= 400:
        return None, f"HTTP {resp.status_code}"

    dest_dir = Path(download_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_filename(resp.url)
    try:
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
    except OSError as exc:
        return None, str(exc)
    return str(dest), None


def check_redirect_chain(session: requests.Session, base_url: str, max_hops: int = 10) -> list:
    """Follow redirects manually (instead of letting requests do it silently)
    so 301/302/etc hops are visible, and detect loops."""
    findings = []
    current = base_url
    seen = set()
    for _ in range(max_hops):
        if current in seen:
            findings.append(("redirect", f"Redirect loop detected at {current}"))
            break
        seen.add(current)
        try:
            resp = session.get(current, timeout=8, allow_redirects=False)
        except RequestException as exc:
            findings.append(("error", f"Could not fetch {current}: {exc}"))
            break
        if resp.status_code in REDIRECT_STATUS_CODES:
            location = resp.headers.get("Location", "")
            if not location:
                findings.append(("redirect", f"{current} -> HTTP {resp.status_code} with no Location header"))
                break
            next_url = urljoin(current, location)
            label = REDIRECT_LABELS.get(resp.status_code, f"HTTP {resp.status_code}")
            findings.append(("redirect", f"{current} -> {resp.status_code} {label} -> {next_url}"))
            current = next_url
        else:
            break
    return findings


def check_sensitive_paths(session: requests.Session, base_url: str, download_dir: str = None) -> list:
    findings = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url + "/", path)
        try:
            resp = session.get(url, timeout=8, allow_redirects=False)
        except RequestException:
            continue

        target_url = url
        if resp.status_code in REDIRECT_STATUS_CODES:
            location = resp.headers.get("Location", "")
            label = REDIRECT_LABELS.get(resp.status_code, f"HTTP {resp.status_code}")
            findings.append(("redirect", f"{url} -> {resp.status_code} {label} -> {location or '?'}"))
            if not location:
                continue
            target_url = urljoin(url, location)
        elif resp.status_code >= 400:
            continue
        else:
            findings.append(("exposed_path", f"{url} -> HTTP {resp.status_code}"))

        if download_dir:
            saved, err = download_file(session, target_url, download_dir)
            if saved:
                findings.append(("download", f"Saved {target_url} -> {saved}"))
            else:
                findings.append(("download_error", f"{target_url}: {err}"))
    return findings


def check_tls(hostname: str, port: int = 443) -> list:
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(("tls", f"Certificate EXPIRED {abs(days_left)} days ago"))
                elif days_left < 14:
                    findings.append(("tls", f"Certificate expires soon: {days_left} days left"))
                proto = ssock.version()
                if proto in ("TLSv1", "TLSv1.1"):
                    findings.append(("tls", f"Outdated TLS protocol negotiated: {proto}"))
    except ssl.SSLCertVerificationError as exc:
        findings.append(("tls", f"Certificate verification failed: {exc}"))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        findings.append(("tls", f"Could not establish TLS connection: {exc}"))
    return findings


def check_robots_sitemap(session: requests.Session, base_url: str) -> list:
    findings = []
    for path in ("robots.txt", "sitemap.xml"):
        url = f"{base_url}/{path}"
        try:
            resp = session.get(url, timeout=8)
        except RequestException:
            continue
        if resp.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(\S+)", resp.text)
            if disallowed:
                findings.append(("info", f"{url} lists {len(disallowed)} Disallow entries (possible hidden paths)"))
    return findings


def severity_color(kind: str) -> str:
    return {
        "missing_header": YELLOW,
        "version_disclosure": YELLOW,
        "cookie_flags": YELLOW,
        "exposed_path": RED,
        "tls": RED,
        "redirect": YELLOW,
        "download": GREEN,
        "download_error": YELLOW,
        "info": BLUE,
        "error": RED,
    }.get(kind, RESET)


def run_scan(target: str, timeout: int = 10, download_dir: str = None, resolve_ip: str = None) -> int:
    base_url = normalize_target(target)
    hostname = urlparse(base_url).hostname

    print(f"{BOLD}Target:{RESET} {base_url}")
    if resolve_ip:
        print(f"{BOLD}DNS override:{RESET} {hostname} -> {resolve_ip}")
    print(f"{BOLD}Started:{RESET} {datetime.now(timezone.utc).isoformat()}\n")

    session = requests.Session()
    session.headers.update({"User-Agent": "THEDAY-Scanner/1.0 (authorized-testing)"})

    all_findings = []
    with dns_override(hostname, resolve_ip):
        all_findings += check_redirect_chain(session, base_url)
        all_findings += check_security_headers(session, base_url)
        all_findings += check_sensitive_paths(session, base_url, download_dir=download_dir)
        all_findings += check_robots_sitemap(session, base_url)
        if base_url.startswith("https://") and hostname:
            all_findings += check_tls(hostname)

    all_findings = list(dict.fromkeys(all_findings))

    if not all_findings:
        print(f"{GREEN}No issues found with current checks.{RESET}")
        return 0

    print(f"{BOLD}Findings:{RESET}\n")
    for kind, detail in all_findings:
        color = severity_color(kind)
        print(f"{color}[{kind.upper()}]{RESET} {clean(detail)}")

    print(f"\n{BOLD}Total findings:{RESET} {len(all_findings)}")
    non_failing = {"info", "redirect", "download"}
    return 1 if any(k not in non_failing for k, _ in all_findings) else 0


def main():
    parser = argparse.ArgumentParser(
        description="THEDAY - authorized web recon / misconfiguration scanner."
    )
    parser.add_argument("target", help="Target URL or hostname (must be authorized for testing)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")
    parser.add_argument(
        "--download",
        metavar="DIR",
        help="Download exposed/redirected resources found during the scan into DIR",
    )
    parser.add_argument(
        "--resolve",
        metavar="IP",
        help=(
            "Force DNS resolution of target's hostname to this IP (like `curl --resolve`), "
            "e.g. to reach an origin server directly, bypassing a CDN/WAF's DNS record. "
            "Host header/SNI/cert check still use the real hostname from `target`. "
            "Example: theday.py example.com --resolve 203.0.113.10"
        ),
    )
    args = parser.parse_args()

    if args.resolve:
        try:
            ipaddress.ip_address(args.resolve)
        except ValueError:
            parser.error(f"--resolve expects an IP address, got {args.resolve!r}")

    if not args.no_banner:
        print_banner()

    try:
        sys.exit(
            run_scan(
                args.target,
                timeout=args.timeout,
                download_dir=args.download,
                resolve_ip=args.resolve,
            )
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Scan interrupted.{RESET}")
        sys.exit(130)


if __name__ == "__main__":
    main()
