#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H4X Toolkit v3.1 Safe Lab Edition
=================================

إطار اختبار أمني مخصص للأنظمة التي تملكها أو لديك إذن صريح باختبارها.

المزايا:
  1) Recon      : DNS / WHOIS / Headers / Tech hints
  2) Scan       : TCP port scanner
  3) Dirs       : فحص مسارات الويب من wordlist
  4) Web Audit  : فحص أمني غير استغلالي لترويسات HTTP/TLS
  5) Sniff      : إحصاءات حركة شبكية فقط (بدون قراءة بيانات الدخول)
  6) Report     : تقرير HTML للجلسة

ملاحظات أمان:
- الأداة ترفض العمل على أهداف خارج scope.txt.
- افتراضيًا تسمح فقط بـ localhost والشبكات الخاصة.
- لا تتضمن brute-force لكلمات المرور أو التقاط بيانات اعتماد أو payloads استغلالية.

التثبيت على Kali:
    sudo apt update
    sudo apt install -y python3 python3-pip nmap whois dnsutils
    python3 -m venv .venv
    source .venv/bin/activate
    pip install requests scapy

التشغيل:
    chmod +x h4x_toolkit_safe.py
    ./h4x_toolkit_safe.py

أو:
    python3 h4x_toolkit_safe.py

يمكنك إضافة أهداف مصرح بها إلى:
    scope.txt
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlparse, urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    raise SystemExit("[!] ثبّت requests: pip install requests")


# ============================================================================
# الإعدادات والحالة
# ============================================================================

APP_NAME = "H4X Toolkit"
VERSION = "3.1-safe"
BASE_DIR = Path(__file__).resolve().parent
SCOPE_FILE = BASE_DIR / "scope.txt"
LOG_FILE = BASE_DIR / "h4x.log"
DEFAULT_REPORT = BASE_DIR / "report.html"


@dataclass(slots=True)
class Config:
    request_timeout: float = 8.0
    socket_timeout: float = 1.0
    max_workers: int = 32
    scan_workers: int = 128
    verify_tls: bool = True
    user_agent: str = f"{APP_NAME}/{VERSION}"


@dataclass
class Finding:
    category: str
    target: str
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


@dataclass
class AppState:
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    findings: list[Finding] = field(default_factory=list)

    def add(self, category: str, target: str, details: object) -> None:
        self.findings.append(Finding(category, target, str(details)))


CONFIG = Config()
STATE = AppState()
_THREAD_LOCAL = threading.local()


# ============================================================================
# Logging
# ============================================================================

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("h4x")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(fmt)

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(fmt)

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger


LOG = setup_logging()


# ============================================================================
# HTTP session لكل Thread
# ============================================================================

def get_session() -> requests.Session:
    if not hasattr(_THREAD_LOCAL, "session"):
        session = requests.Session()
        session.headers.update({"User-Agent": CONFIG.user_agent})

        adapter = HTTPAdapter(
            pool_connections=CONFIG.max_workers,
            pool_maxsize=CONFIG.max_workers,
            max_retries=0,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        _THREAD_LOCAL.session = session

    return _THREAD_LOCAL.session


# ============================================================================
# Scope / Validation
# ============================================================================

DEFAULT_SCOPE = """# H4X Toolkit authorized scope
# أضف هنا فقط الأنظمة التي تملكها أو لديك إذن باختبارها.
localhost
127.0.0.1
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
"""


def ensure_scope_file() -> None:
    if not SCOPE_FILE.exists():
        SCOPE_FILE.write_text(DEFAULT_SCOPE, encoding="utf-8")
        LOG.info("تم إنشاء %s", SCOPE_FILE)


def normalize_host(value: str) -> str:
    value = value.strip()

    if not value:
        raise ValueError("الهدف فارغ.")

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""

    value = value.strip().rstrip(".")
    if not value:
        raise ValueError("تعذر استخراج اسم المضيف.")

    if len(value) > 253:
        raise ValueError("اسم المضيف طويل جدًا.")

    return value


def normalize_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("يسمح فقط بروابط http:// و https://")

    if not parsed.hostname:
        raise ValueError("الرابط لا يحتوي على hostname صالح.")

    return value


def resolve_ips(host: str) -> set[ipaddress._BaseAddress]:
    ips: set[ipaddress._BaseAddress] = set()

    try:
        for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            addr = info[4][0]
            try:
                ips.add(ipaddress.ip_address(addr))
            except ValueError:
                pass
    except socket.gaierror as exc:
        raise ValueError(f"تعذر حل DNS للهدف {host}: {exc}") from exc

    return ips


class Scope:
    def __init__(self, path: Path):
        self.path = path
        self.hosts: set[str] = set()
        self.networks: list[ipaddress._BaseNetwork] = []
        self.reload()

    def reload(self) -> None:
        self.hosts.clear()
        self.networks.clear()

        for raw in self.path.read_text(encoding="utf-8").splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue

            if entry == "localhost":
                self.hosts.add("localhost")
                continue

            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass

            self.hosts.add(entry.lower().rstrip("."))

    def allows(self, host: str) -> bool:
        host = normalize_host(host)
        lowered = host.lower()

        if lowered in self.hosts:
            return True

        # IP مباشر
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in network for network in self.networks)
        except ValueError:
            pass

        # اسم نطاق: إذا كان مصرحًا به بالاسم نقبله.
        if lowered in self.hosts:
            return True

        # إذا لم يكن الاسم نفسه في scope نرفضه حتى لو حل إلى IP خاص.
        # هذا يمنع تشغيل فحص على اسم نطاق لم تتم إضافته صراحة.
        return False


ensure_scope_file()
SCOPE = Scope(SCOPE_FILE)


def require_scope(value: str) -> str:
    host = normalize_host(value)

    if not SCOPE.allows(host):
        raise PermissionError(
            f"الهدف '{host}' غير موجود في scope.txt.\n"
            f"أضفه فقط إذا كان ملكك أو لديك تصريح صريح لاختباره."
        )

    # للـ domain المصرح به: تحذير إذا لم يُحل.
    try:
        resolve_ips(host)
    except ValueError:
        if host not in {"localhost"}:
            LOG.warning("الهدف مصرح بالاسم لكن DNS لم يُحل: %s", host)

    return host


def require_url_scope(url: str) -> str:
    url = normalize_url(url)
    host = urlparse(url).hostname or ""
    require_scope(host)
    return url


# ============================================================================
# Helpers
# ============================================================================

def read_wordlist(path: str) -> list[str]:
    p = Path(path).expanduser()

    if not p.is_file():
        raise FileNotFoundError(f"القائمة غير موجودة: {p}")

    words: list[str] = []
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)

    return words


def bounded_map(
    worker,
    items: Iterable,
    workers: int,
) -> Iterator:
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        yield from pool.map(worker, items)


def run_command(args: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(f"الأمر غير مثبت: {args[0]}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"انتهت مهلة الأمر: {args[0]}")

    if result.returncode not in (0, 1):
        stderr = result.stderr.strip()
        if stderr:
            LOG.debug("%s stderr: %s", args[0], stderr[:500])

    return result.stdout.strip()


# ============================================================================
# 1) RECON
# ============================================================================

def recon_whois(domain: str) -> list[str]:
    require_scope(domain)

    output = run_command(["whois", domain], timeout=30)
    interesting: list[str] = []

    pattern = re.compile(
        r"^(Registrar|Creation|Created|Expiry|Expiration|Name Server|OrgName|Country)",
        re.I,
    )

    for line in output.splitlines():
        if pattern.search(line.strip()):
            interesting.append(line.strip())

    return interesting[:100]


def recon_dns(domain: str) -> dict[str, list[str]]:
    require_scope(domain)

    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            output = run_command(["dig", "+short", rtype, domain], timeout=10)
        except RuntimeError as exc:
            if "غير مثبت" in str(exc):
                raise RuntimeError("ثبّت dnsutils: sudo apt install dnsutils") from exc
            raise

        if output:
            records[rtype] = output.splitlines()

    return records


def recon_headers(url: str) -> dict:
    require_url_scope(url)
    session = get_session()

    try:
        response = session.get(
            url,
            timeout=CONFIG.request_timeout,
            verify=CONFIG.verify_tls,
            allow_redirects=True,
        )
        return {
            "status": response.status_code,
            "final_url": response.url,
            "length": len(response.content),
            "headers": dict(response.headers),
        }
    except requests.RequestException as exc:
        return {"error": str(exc)}


def recon_tech(url: str) -> list[str]:
    require_url_scope(url)
    session = get_session()

    try:
        response = session.get(
            url,
            timeout=CONFIG.request_timeout,
            verify=CONFIG.verify_tls,
        )
    except requests.RequestException as exc:
        LOG.warning("فشل HTTP tech probe: %s", exc)
        return []

    text = response.text[:2_000_000]
    headers = response.headers
    found: list[str] = []

    if "Server" in headers:
        found.append(f"Server: {headers['Server']}")

    if "X-Powered-By" in headers:
        found.append(f"X-Powered-By: {headers['X-Powered-By']}")

    signatures = (
        ("wp-content", "WordPress"),
        ("Drupal", "Drupal"),
        ("Joomla", "Joomla"),
        ("/cdn-cgi/", "Cloudflare"),
        ("__NEXT_DATA__", "Next.js"),
        ("laravel_session", "Laravel"),
    )

    for signature, name in signatures:
        if signature.lower() in text.lower():
            found.append(name)

    # إزالة التكرار مع الحفاظ على الترتيب
    return list(dict.fromkeys(found))


# ============================================================================
# 2) PORT SCAN
# ============================================================================

def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            left, right = part.split("-", 1)
            start, end = int(left), int(right)

            if start > end:
                start, end = end, start

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("المنافذ يجب أن تكون بين 1 و 65535.")

            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("المنافذ يجب أن تكون بين 1 و 65535.")
            ports.add(port)

    if not ports:
        raise ValueError("لم يتم تحديد منافذ صالحة.")

    return sorted(ports)


def scan_ports(target: str, ports: str = "1-1000") -> list[tuple[int, str]]:
    target = require_scope(target)
    port_list = parse_ports(ports)

    LOG.info("فحص %d منفذ على %s", len(port_list), target)

    def probe(port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONFIG.socket_timeout)

        try:
            if sock.connect_ex((target, port)) != 0:
                return None

            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            return port, service
        except OSError as exc:
            LOG.debug("Socket %s:%d: %s", target, port, exc)
            return None
        finally:
            sock.close()

    found: list[tuple[int, str]] = []
    workers = min(CONFIG.scan_workers, max(1, len(port_list)))

    for result in bounded_map(probe, port_list, workers):
        if result:
            found.append(result)
            print(f"  [+] {result[0]}/tcp open  ({result[1]})")

    return found


def scan_nmap(target: str, ports: str = "") -> int:
    target = require_scope(target)

    if not shutil.which("nmap"):
        raise RuntimeError("nmap غير مثبت: sudo apt install nmap")

    cmd = ["nmap", "-sV", "-T3"]

    if ports:
        parse_ports(ports)
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["--top-ports", "500"])

    cmd.append(target)

    LOG.info("تشغيل nmap على %s", target)
    return subprocess.call(cmd)


# ============================================================================
# 3) DIRECTORY CHECK
# ============================================================================

def dir_check(
    base_url: str,
    wordlist: str,
    extensions: tuple[str, ...] = ("", ".php", ".html", ".txt"),
    allowed_codes: tuple[int, ...] = (200, 204, 301, 302, 307, 308, 401, 403),
) -> list[tuple[str, int, int]]:
    base_url = require_url_scope(base_url)
    words = read_wordlist(wordlist)

    session = get_session()
    found: list[tuple[str, int, int]] = []

    def targets() -> Iterator[str]:
        for word in words:
            safe_word = word.lstrip("/")
            for ext in extensions:
                yield urljoin(base_url.rstrip("/") + "/", safe_word + ext)

    def check(url: str):
        # كل URL مبني على base URL مصرح به.
        try:
            response = session.get(
                url,
                timeout=CONFIG.request_timeout,
                allow_redirects=False,
                verify=CONFIG.verify_tls,
            )
            if response.status_code in allowed_codes:
                return url, response.status_code, len(response.content)
        except requests.RequestException as exc:
            LOG.debug("DIR request failed %s: %s", url, exc)

        return None

    workers = min(CONFIG.max_workers, 32)

    for result in bounded_map(check, targets(), workers):
        if result:
            found.append(result)
            print(f"  [+] {result[1]}  {result[0]}  ({result[2]} bytes)")

    return found


# ============================================================================
# 4) WEB SECURITY AUDIT (non-exploitative)
# ============================================================================

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def web_audit(url: str) -> dict:
    url = require_url_scope(url)
    session = get_session()

    try:
        response = session.get(
            url,
            timeout=CONFIG.request_timeout,
            verify=CONFIG.verify_tls,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}

    missing = [name for name in SECURITY_HEADERS if name not in response.headers]

    cookies = []
    for cookie in response.cookies:
        cookies.append({
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "has_domain": bool(cookie.domain),
        })

    result = {
        "status": response.status_code,
        "final_url": response.url,
        "https": response.url.lower().startswith("https://"),
        "missing_security_headers": missing,
        "server": response.headers.get("Server"),
        "x_powered_by": response.headers.get("X-Powered-By"),
        "cookies": cookies,
    }

    return result


def tls_info(host: str, port: int = 443) -> dict:
    host = require_scope(host)

    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=CONFIG.request_timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {
                "version": tls.version(),
                "cipher": tls.cipher(),
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
            }


# ============================================================================
# 5) SNIFF — metadata only
# ============================================================================

def sniff_stats(interface: str, count: int = 50) -> dict:
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP
    except ImportError as exc:
        raise RuntimeError("ثبّت scapy: pip install scapy") from exc

    if count < 1 or count > 10000:
        raise ValueError("عدد الحزم يجب أن يكون بين 1 و10000.")

    stats = {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "other": 0,
        "endpoints": {},
    }

    def callback(pkt):
        stats["total"] += 1

        if TCP in pkt:
            stats["tcp"] += 1
        elif UDP in pkt:
            stats["udp"] += 1
        else:
            stats["other"] += 1

        src = dst = None
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst

        if src:
            stats["endpoints"][src] = stats["endpoints"].get(src, 0) + 1
        if dst:
            stats["endpoints"][dst] = stats["endpoints"].get(dst, 0) + 1

    sniff(
        iface=interface,
        prn=callback,
        count=count,
        store=False,
    )

    top = sorted(
        stats["endpoints"].items(),
        key=lambda item: item[1],
        reverse=True,
    )[:20]
    stats["endpoints"] = dict(top)

    return stats


# ============================================================================
# 6) REPORT
# ============================================================================

def report_save(path: Path = DEFAULT_REPORT) -> Path:
    rows: list[str] = []

    for finding in STATE.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.timestamp)}</td>"
            f"<td>{html.escape(finding.category)}</td>"
            f"<td>{html.escape(finding.target)}</td>"
            f"<td><pre>{html.escape(finding.details)}</pre></td>"
            "</tr>"
        )

    body = "\n".join(rows) or (
        '<tr><td colspan="4">لا توجد نتائج مسجلة في هذه الجلسة.</td></tr>'
    )

    document = f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>H4X Toolkit Report</title>
<style>
:root {{ color-scheme: dark; }}
body {{
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  background: #101214;
  color: #e8e8e8;
  margin: 2rem;
}}
h1 {{ margin-bottom: .25rem; }}
small {{ color: #aaa; }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 1.5rem;
}}
th, td {{
  border: 1px solid #343a40;
  padding: .7rem;
  text-align: right;
  vertical-align: top;
}}
th {{ background: #1c2024; }}
tr:nth-child(even) {{ background: #15191d; }}
pre {{
  margin: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-family: ui-monospace, monospace;
}}
</style>
</head>
<body>
<h1>H4X Toolkit Report</h1>
<small>Version {html.escape(VERSION)} — started {html.escape(STATE.started_at)}</small>
<table>
<thead>
<tr>
  <th>الوقت</th>
  <th>النوع</th>
  <th>الهدف</th>
  <th>التفاصيل</th>
</tr>
</thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>
"""

    path.write_text(document, encoding="utf-8")
    LOG.info("تم حفظ التقرير: %s", path)
    return path


# ============================================================================
# UI
# ============================================================================

BANNER = r"""
  _   _  _  _  __  __   _____           _ _    _ _
 | | | || || ||  \/  | |_   _|__   ___ | | | _(_) |_
 | |_| || || || |\/| |   | |/ _ \ / _ \| | |/ / | __|
 |  _  ||__   _| |  | |   | | (_) | (_) | |   <| | |_
 |_| |_|   |_| |_|  |_|   |_|\___/ \___/|_|_|\_\_|\__|

 H4X Toolkit v3.1 Safe Lab Edition
 Authorized environments only
"""

MENU = """
  1) recon       — DNS / WHOIS / Headers / Tech hints
  2) scan        — TCP scanner / nmap
  3) dirs        — Web path checks from wordlist
  4) web-audit   — Security headers + TLS information
  5) sniff       — Packet statistics only
  6) report      — Save HTML report
  7) reload      — Reload scope.txt
  0) exit
"""


def print_json(data: object) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def cmd_recon() -> None:
    domain = input("النطاق/المضيف: ").strip()
    domain = require_scope(domain)

    print("\n[*] DNS")
    dns = recon_dns(domain)
    print_json(dns)

    print("\n[*] WHOIS")
    try:
        whois = recon_whois(domain)
        for line in whois:
            print(" ", line)
    except RuntimeError as exc:
        whois = [str(exc)]
        print(f"[!] {exc}")

    scheme = input("\nالرابط للفحص [مثال http://127.0.0.1]: ").strip()

    headers = {}
    tech = []
    if scheme:
        scheme = require_url_scope(scheme)
        headers = recon_headers(scheme)
        tech = recon_tech(scheme)

        print("\n[*] Tech")
        print_json(tech)

        print("\n[*] Headers")
        print_json(headers)

    STATE.add(
        "recon",
        domain,
        json.dumps(
            {"dns": dns, "whois": whois, "tech": tech, "headers": headers},
            ensure_ascii=False,
            default=str,
        ),
    )


def cmd_scan() -> None:
    target = input("الهدف: ").strip()
    require_scope(target)

    mode = input("1) internal scanner  2) nmap [1]: ").strip() or "1"
    ports = input("المنافذ [1-1000]: ").strip() or "1-1000"

    if mode == "2":
        scan_nmap(target, ports)
        STATE.add("nmap", target, f"ports={ports}")
    else:
        result = scan_ports(target, ports)
        STATE.add("port-scan", target, result)


def cmd_dirs() -> None:
    url = input("الرابط الأساسي: ").strip()
    require_url_scope(url)

    default = "/usr/share/wordlists/dirb/common.txt"
    wordlist = input(f"القائمة [{default}]: ").strip() or default

    result = dir_check(url, wordlist)
    STATE.add("dirs", url, result)


def cmd_web_audit() -> None:
    url = input("الرابط: ").strip()
    url = require_url_scope(url)

    audit = web_audit(url)
    print_json(audit)
    STATE.add("web-audit", url, audit)

    host = urlparse(url).hostname or ""
    if url.lower().startswith("https://"):
        try:
            info = tls_info(host)
            print("\n[*] TLS")
            print_json(info)
            STATE.add("tls", host, info)
        except Exception as exc:
            LOG.warning("TLS audit failed: %s", exc)


def cmd_sniff() -> None:
    interface = input("الواجهة [eth0]: ").strip() or "eth0"
    count_raw = input("عدد الحزم [50]: ").strip() or "50"
    count = int(count_raw)

    print("[*] يتم جمع metadata فقط، بدون قراءة payloads أو بيانات اعتماد.")
    result = sniff_stats(interface, count)
    print_json(result)
    STATE.add("sniff-stats", interface, result)


def cmd_loop() -> None:
    print(BANNER)
    print(f"Scope file: {SCOPE_FILE}")
    print(f"Log file  : {LOG_FILE}\n")

    while True:
        print(MENU)
        choice = input("h4x > ").strip().lower()

        try:
            if choice in {"0", "exit", "quit"}:
                break

            if choice == "1":
                cmd_recon()

            elif choice == "2":
                cmd_scan()

            elif choice == "3":
                cmd_dirs()

            elif choice == "4":
                cmd_web_audit()

            elif choice == "5":
                cmd_sniff()

            elif choice == "6":
                path = report_save()
                print(f"[+] التقرير: {path}")

            elif choice == "7":
                SCOPE.reload()
                print("[+] أعيد تحميل scope.txt")

            else:
                print("[!] اختيار غير معروف.")

        except KeyboardInterrupt:
            print("\n[!] أُلغيت العملية الحالية.")

        except PermissionError as exc:
            print(f"[!] Scope رفض الهدف:\n{exc}")

        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            print(f"[!] {exc}")

        except requests.RequestException as exc:
            LOG.error("HTTP error: %s", exc)
            print(f"[!] خطأ HTTP: {exc}")

        except Exception as exc:
            LOG.exception("Unhandled error")
            print(f"[!] خطأ غير متوقع: {exc}")

    print("[+] انتهت الجلسة.")


def main() -> None:
    LOG.info("%s %s started", APP_NAME, VERSION)
    cmd_loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] أُوقفت يدويًا.")
