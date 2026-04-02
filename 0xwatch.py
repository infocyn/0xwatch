#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   0xWatch — Domain Seizure Intelligence Platform                    ║
║   Professional domain monitoring & threat detection engine          ║
║   v1.0.0                                                            ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import json
import signal
import hashlib
import argparse
import tempfile
import random
import ssl
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Dependencies ──────────────────────────────────────────────────────
try:
    import dns.resolver
    import requests
    from dotenv import load_dotenv
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.rule import Rule
    from rich.padding import Padding
    from rich.style import Style
    from rich import box as rich_box
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Run: pip install rich requests dnspython python-whois beautifulsoup4 PySocks urllib3 python-dotenv")
    sys.exit(1)

try:
    import whois as pywhois
except ImportError:
    pywhois = None

import logging
logging.getLogger("whois").setLevel(logging.CRITICAL)

load_dotenv()
console = Console()

# ── Version & Paths ───────────────────────────────────────────────────
VERSION       = "1.0.0"
TOOL_NAME     = "0xWatch"
TOOL_SUBTITLE = "Domain Seizure Intelligence Platform"

STATE_FILE       = Path("0xwatch_dns.json")
ONION_STATE_FILE = Path("0xwatch_onion.json")
HTTP_STATE_FILE  = Path("0xwatch_http.json")
WHOIS_STATE_FILE = Path("0xwatch_whois.json")
IP_STATE_FILE    = Path("0xwatch_ip.json")
SSL_STATE_FILE   = Path("0xwatch_ssl.json")
SCORE_FILE       = Path("0xwatch_scores.json")
EVENT_FEED_FILE  = Path("0xwatch_events.json")
SITES_FILE       = Path("monitored_sites.json")
SCREENSHOT_DIR   = Path("screenshots")
SCREENSHOT_DIR.mkdir(exist_ok=True)

# ── Constants ─────────────────────────────────────────────────────────
DNS_RECORDS      = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
DNS_TIMEOUT      = 5
SCAN_INTERVAL    = 15
REQUEST_TIMEOUT  = 15
ONION_TIMEOUT    = 30
HTTP_CONCURRENCY = 10
WHOIS_CONCURRENCY= 5

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# Seizure signals
SEIZURE_KEYWORDS = [
    "this hidden site has been seized","this domain has been seized","this site has been seized",
    "this website has been seized","seized by the fbi","seized by the united states",
    "seized by law enforcement","department of justice","seized pursuant to",
    "seized by europol","seized by interpol","national crime agency","bundeskriminalamt",
    "politie nederland","seized by afp","australian federal police","seized by garda",
    "joint law enforcement operation","law enforcement operation","forfeiture order",
    "seized by bka","seized and shut down","warrant issued",
]
WHOIS_SEIZURE_INDICATORS = [
    "department of justice","u.s. government","law enforcement","seized","europol","interpol",
    "national crime agency","fbi","ice homeland security","markmonitor","usdoj","justice gov",
    "usssdomainseizure","forfeiture",
]
DNS_SEIZURE_PATTERNS = [
    "fbi.seized","seized.gov","europol","interpol","seized","usssdomainseizure",
    "nca.police.uk","doj.gov","justice.gov",
]
LE_CA_ORGS = [
    "department of justice","united states government","u.s. government","law enforcement",
    "fbi","europol","ncsc","national crime agency","bundeskriminalamt",
]

# Risk scoring weights
RISK_WEIGHTS = {
    "dns_seizure_keyword":    50,
    "http_seizure_keyword":   45,
    "whois_seizure_indicator":40,
    "ssl_le_ca":              35,
    "ssl_issuer_change":      20,
    "ssl_expiry_drop":        25,
    "ip_le_rdns":             30,
    "dns_ns_change":          15,
    "http_body_change":       15,
    "whois_registrar_change": 10,
    "http_redirect_gov":      40,
    "ip_change":              10,
    "dns_a_change":           12,
}
ALERT_THRESHOLD = 40   # fire alerts only when risk score >= this

# ── Color palette ─────────────────────────────────────────────────────
C = {
    "cyan":    "#00d4ff",
    "green":   "#00ff99",
    "red":     "#ff3355",
    "yellow":  "#ffcc00",
    "magenta": "#cc66ff",
    "orange":  "#ff8800",
    "dim":     "#445566",
    "white":   "#e8f0f8",
    "header":  "#001a2e",
}

# ══════════════════════════════════════════════════════════════════════
# UI HELPERS
# ══════════════════════════════════════════════════════════════════════

BANNER = r"""
  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ██╔═████╗╚██╗██╔╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ██║██╔██║ ╚███╔╝ ██║ █╗ ██║███████║   ██║   ██║     ███████║
 ████╔╝██║ ██╔██╗ ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝"""

def print_banner():
    console.print(f"[bold {C['cyan']}]{BANNER}[/]")
    console.print()
    console.print(
        f"  [bold {C['cyan']}]{TOOL_NAME}[/] "
        f"[{C['dim']}]v{VERSION}[/]"
        f"  [bold white]—[/]  "
        f"[{C['dim']}]{TOOL_SUBTITLE}[/]"
    )
    console.print(f"  [{C['dim']}]{'─'*68}[/]")
    console.print()

def section_rule(title: str, color: str = C['cyan']):
    console.print()
    console.print(Rule(f"[bold {color}]  {title}  [/]", style=color, align="left"))
    console.print()

def alert_box(level: str, domain: str, message: str, details: dict = None):
    """Print a rich alert box for detected events."""
    colors = {
        "SEIZURE":  C['red'],
        "CHANGE":   C['yellow'],
        "INFO":     C['cyan'],
        "NEW":      C['green'],
        "SSL":      C['magenta'],
        "SCORE":    C['orange'],
    }
    icons = {
        "SEIZURE": "🚨",
        "CHANGE":  "⚡",
        "INFO":    "ℹ",
        "NEW":     "✦",
        "SSL":     "🔐",
        "SCORE":   "📊",
    }
    color = colors.get(level, C['white'])
    icon  = icons.get(level, "•")
    ts    = datetime.now().strftime("%H:%M:%S")

    lines = [f"[bold {color}]{icon}  {level}[/bold {color}]   [dim]{domain}[/dim]   [dim]{ts}[/dim]"]
    lines.append(f"[{C['white']}]{message}[/]")
    if details:
        for k, v in details.items():
            lines.append(f"  [dim]{k}:[/dim] [{color}]{v}[/]")

    panel = Panel(
        "\n".join(lines),
        border_style=color,
        padding=(0, 2),
        expand=False,
    )
    console.print(panel)

def status_row(symbol: str, color: str, label: str, value: str = ""):
    console.print(f"  [{color}]{symbol}[/]  [{C['white']}]{label}[/]  [dim]{value}[/dim]")

def risk_bar(score: int, width: int = 20) -> str:
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 70: color = C['red']
    elif score >= 40: color = C['yellow']
    else: color = C['green']
    return f"[{color}]{bar}[/] [{color}]{score:>3}[/][dim]/100[/dim]"

def monitor_badge(name: str, enabled: bool) -> str:
    if enabled:
        return f"[bold black on {C['green']}]  {name} ✓  [/]"
    return f"[bold {C['dim']}]  {name} ✗  [/]"

# ══════════════════════════════════════════════════════════════════════
# STATE & DATA MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

def atomic_write_json(path: Path, data: dict):
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        if tmp.exists():
            tmp.unlink()

class StateManager:
    def __init__(self, path: Path):
        self.path = path
        self.data: Dict = {}
        self._lock = threading.Lock()

    def load(self):
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {}

    def save(self):
        with self._lock:
            atomic_write_json(self.path, self.data)

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value):
        self.data[key] = value


class RiskScorer:
    """Aggregate multi-monitor signals into a 0-100 risk score per domain."""

    def __init__(self, path: Path = SCORE_FILE):
        self.path = path
        self.scores: Dict[str, Dict] = {}
        self.load()

    def load(self):
        if self.path.exists():
            try:
                self.scores = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.scores = {}

    def save(self):
        atomic_write_json(self.path, self.scores)

    def add_signal(self, domain: str, signal: str, description: str = ""):
        pts = RISK_WEIGHTS.get(signal, 5)
        if domain not in self.scores:
            self.scores[domain] = {"score": 0, "signals": [], "updated": ""}
        entry = self.scores[domain]
        entry["score"] = min(100, entry["score"] + pts)
        entry["signals"].append({
            "signal": signal,
            "points": pts,
            "description": description,
            "time": datetime.now(timezone.utc).isoformat(),
        })
        entry["updated"] = datetime.now(timezone.utc).isoformat()
        self.save()
        return entry["score"]

    def get_score(self, domain: str) -> int:
        return self.scores.get(domain, {}).get("score", 0)

    def get_signals(self, domain: str) -> list:
        return self.scores.get(domain, {}).get("signals", [])

    def reset(self, domain: str):
        if domain in self.scores:
            self.scores[domain]["score"] = 0
            self.scores[domain]["signals"] = []
            self.save()

    def top_domains(self, n: int = 10) -> List[Tuple[str, int]]:
        return sorted(
            [(d, v["score"]) for d, v in self.scores.items()],
            key=lambda x: -x[1]
        )[:n]


class EventFeed:
    MAX = 1000

    def __init__(self):
        self.events: List[Dict] = []
        if EVENT_FEED_FILE.exists():
            try:
                self.events = json.loads(EVENT_FEED_FILE.read_text(encoding="utf-8"))
            except Exception:
                self.events = []

    def add(self, event_type: str, domain: str, data: dict):
        entry = {
            "id":        hashlib.sha1(f"{event_type}{domain}{time.time()}".encode()).hexdigest()[:12],
            "type":      event_type,
            "domain":    domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      data,
        }
        self.events.insert(0, entry)
        self.events = self.events[:self.MAX]
        atomic_write_json(EVENT_FEED_FILE, self.events)
        return entry


class SiteManager:
    def __init__(self):
        self.domains:     List[str] = []
        self.onion_sites: List[str] = []
        self.load()

    def load(self):
        if not SITES_FILE.exists():
            self._write({"clearnet": [], "onion": []})
        try:
            raw = json.loads(SITES_FILE.read_text(encoding="utf-8"))
            self.domains     = [d.strip().lower() for d in raw.get("clearnet", []) if d.strip()]
            self.onion_sites = [s.strip().lower() for s in raw.get("onion", [])    if s.strip()]
        except Exception:
            self.domains = []
            self.onion_sites = []

    def reload(self) -> Tuple[int, int]:
        old_d, old_o = len(self.domains), len(self.onion_sites)
        self.load()
        return len(self.domains), len(self.onion_sites)

    def _write(self, data: dict):
        atomic_write_json(SITES_FILE, data)

    def _save(self):
        self._write({"clearnet": self.domains, "onion": self.onion_sites})

    def add(self, site: str) -> Tuple[str, bool]:
        site = site.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
        if not site:
            return "invalid", False
        if site.endswith(".onion"):
            if site in self.onion_sites:
                return "onion", False
            self.onion_sites.append(site)
            self._save()
            return "onion", True
        if re.match(r'^[a-z0-9\-\.]+\.[a-z]{2,}$', site):
            if site in self.domains:
                return "clearnet", False
            self.domains.append(site)
            self._save()
            return "clearnet", True
        return "invalid", False

    def remove(self, site: str) -> Tuple[str, bool]:
        site = site.strip().lower()
        if site in self.domains:
            self.domains.remove(site)
            self._save()
            return "clearnet", True
        if site in self.onion_sites:
            self.onion_sites.remove(site)
            self._save()
            return "onion", True
        return "unknown", False


# ══════════════════════════════════════════════════════════════════════
# NOTIFIER
# ══════════════════════════════════════════════════════════════════════

class Notifier:
    def __init__(self):
        self.webhook_url   = os.getenv("DISCORD_WEBHOOK", "")
        self.tg_token      = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.tg_chat       = os.getenv("TELEGRAM_CHAT_ID", "")
        self.session       = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def _post(self, url: str, data: dict = None, files=None, timeout: int = 15):
        try:
            if files:
                r = self.session.post(url, data={"payload_json": json.dumps(data)}, files=files, timeout=timeout)
            else:
                r = self.session.post(url, json=data, timeout=timeout)
            r.raise_for_status()
        except Exception:
            pass

    def _discord_color(self, level: str) -> int:
        return {"SEIZURE": 0xFF3355, "CHANGE": 0xFFCC00, "NEW": 0x00FF99,
                "SSL": 0xCC66FF, "SCORE": 0xFF8800}.get(level, 0x00D4FF)

    def send(self, level: str, domain: str, title: str, fields: List[dict],
             screenshot: str = None, score: int = None):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        # Risk bar
        if score is not None:
            bar = "█" * int(score / 10) + "░" * (10 - int(score / 10))
            fields.append({"name": "Risk Score", "value": f"`{bar}` {score}/100", "inline": False})
        fields.append({"name": "Detected", "value": ts, "inline": True})
        fields.append({"name": "Tool", "value": f"{TOOL_NAME} v{VERSION}", "inline": True})

        embed = {
            "title":       f"{'🚨' if level=='SEIZURE' else '⚡'} {title}",
            "description": f"**Domain:** `{domain}`",
            "color":       self._discord_color(level),
            "fields":      fields,
            "footer":      {"text": f"{TOOL_NAME} v{VERSION} · {TOOL_SUBTITLE}"},
        }
        if screenshot and Path(screenshot).exists():
            embed["image"] = {"url": "attachment://capture.png"}
            with open(screenshot, "rb") as f:
                self._post(self.webhook_url, data={"embeds": [embed]},
                           files={"file": ("capture.png", f, "image/png")})
        elif self.webhook_url:
            self._post(self.webhook_url, data={"embeds": [embed]})

        # Telegram
        if self.tg_token and self.tg_chat:
            lines = [f"{'🚨' if level=='SEIZURE' else '⚡'} *{title}*", f"Domain: `{domain}`"]
            for fld in fields:
                lines.append(f"*{fld['name']}:* {fld['value']}")
            msg = "\n".join(lines)[:4096]
            base = f"https://api.telegram.org/bot{self.tg_token}"
            if screenshot and Path(screenshot).exists():
                with open(screenshot, "rb") as ph:
                    self.session.post(f"{base}/sendPhoto", data={
                        "chat_id": self.tg_chat, "caption": msg[:1024], "parse_mode": "Markdown"
                    }, files={"photo": ph}, timeout=15)
            else:
                self._post(f"{base}/sendMessage", data={
                    "chat_id": self.tg_chat, "text": msg, "parse_mode": "Markdown"
                })


# ══════════════════════════════════════════════════════════════════════
# MONITORS
# ══════════════════════════════════════════════════════════════════════

class DNSMonitor:
    def __init__(self, state: StateManager, notifier: Notifier,
                 scorer: RiskScorer, feed: EventFeed):
        self.state    = state
        self.notifier = notifier
        self.scorer   = scorer
        self.feed     = feed
        self.silent   = False

    def _resolve(self, domain: str, rtype: str) -> Optional[List[str]]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
            return sorted(r.to_text() for r in answers)
        except Exception:
            return None

    def _is_seizure(self, records: List[str]) -> bool:
        combined = " ".join(records).lower()
        return any(p in combined for p in DNS_SEIZURE_PATTERNS)

    def check(self, domain: str, rtype: str) -> bool:
        records = self._resolve(domain, rtype)
        if records is None:
            return False

        key = f"{domain}:{rtype}"
        prev_state = self.state.get(key) or {"records": [], "history": []}
        history    = prev_state.get("history", [])
        is_first   = len(history) == 0

        if not is_first and records == history[-1]:
            return False

        seized  = self._is_seizure(records)
        changed = not is_first

        # Update state
        history.append(records)
        self.state.set(key, {"records": records, "history": history[-10:]})

        if is_first:
            if seized and not self.silent:
                score = self.scorer.add_signal(domain, "dns_seizure_keyword",
                                               f"{rtype}: {', '.join(records)}")
                alert_box("SEIZURE", domain,
                          f"Domain already seized — detected on first scan",
                          {"Record Type": rtype, "Records": ", ".join(records), "Risk Score": str(score)})
                self.notifier.send("SEIZURE", domain, "DNS Seizure Detected (First Scan)",
                                   [{"name": "Record", "value": rtype, "inline": True},
                                    {"name": "Records", "value": ", ".join(records), "inline": False}],
                                   score=score)
                self.feed.add("seizure_dns_first", domain,
                              {"rtype": rtype, "records": records})
            else:
                status_row("✦", C['green'], f"Baselined  {domain}", f"{rtype} → {', '.join(records[:2])}")
            return True

        # Changed
        prev = history[-2] if len(history) >= 2 else []
        if seized:
            score = self.scorer.add_signal(domain, "dns_seizure_keyword",
                                           f"{rtype}: {', '.join(records)}")
            signal_key = "dns_a_change" if rtype == "A" else "dns_ns_change"
            score = self.scorer.add_signal(domain, signal_key)
            if not self.silent:
                alert_box("SEIZURE", domain,
                          f"DNS {rtype} changed — seizure indicators detected!",
                          {"Previous": ", ".join(prev), "New": ", ".join(records),
                           "Risk Score": str(score)})
                self.notifier.send("SEIZURE", domain, f"DNS Seizure — {rtype} Changed",
                                   [{"name": "Previous", "value": ", ".join(prev) or "—", "inline": False},
                                    {"name": "New Records", "value": ", ".join(records), "inline": False}],
                                   score=score)
        else:
            sig = "dns_a_change" if rtype == "A" else ("dns_ns_change" if rtype == "NS" else "ip_change")
            score = self.scorer.add_signal(domain, sig)
            if not self.silent:
                alert_box("CHANGE", domain, f"DNS {rtype} record changed",
                          {"Previous": ", ".join(prev), "New": ", ".join(records)})
                self.notifier.send("CHANGE", domain, f"DNS {rtype} Change Detected",
                                   [{"name": "Previous", "value": ", ".join(prev) or "—", "inline": False},
                                    {"name": "New Records", "value": ", ".join(records), "inline": False}],
                                   score=score)
        self.feed.add("dns_change", domain, {"rtype": rtype, "prev": prev, "new": records, "seized": seized})
        return True

    def scan_all(self, domains: List[str]) -> Dict:
        stats = {"scanned": 0, "changes": 0, "seizures": 0}
        section_rule("DNS MONITOR", C['cyan'])
        table = Table(show_header=True, header_style=f"bold {C['cyan']}", box=rich_box.SIMPLE_HEAVY,
                      border_style=C['dim'], padding=(0, 1))
        table.add_column("Domain", style="white", min_width=30)
        table.add_column("A", justify="center", min_width=6)
        table.add_column("AAAA", justify="center", min_width=6)
        table.add_column("MX", justify="center", min_width=6)
        table.add_column("NS", justify="center", min_width=6)
        table.add_column("TXT", justify="center", min_width=6)
        table.add_column("CNAME", justify="center", min_width=6)
        table.add_column("Status", min_width=14)

        for domain in domains:
            row_results = {}
            domain_seized = False
            domain_changed = False
            for rtype in DNS_RECORDS:
                stats["scanned"] += 1
                changed = self.check(domain, rtype)
                if changed:
                    stats["changes"] += 1
                    row_results[rtype] = "changed"
                    key = f"{domain}:{rtype}"
                    rec = self.state.get(key, {}).get("records", [])
                    if self._is_seizure(rec):
                        domain_seized = True
                        stats["seizures"] += 1
                    domain_changed = True
                else:
                    row_results[rtype] = "ok"
                time.sleep(0.1)

            def cell(rtype):
                r = row_results.get(rtype, "ok")
                if r == "changed":
                    return f"[{C['yellow']}]●[/]" if not domain_seized else f"[{C['red']}]●[/]"
                return f"[{C['dim']}]·[/]"

            status_str = (f"[bold {C['red']}]SEIZURE[/]" if domain_seized
                          else f"[{C['yellow']}]CHANGED[/]" if domain_changed
                          else f"[{C['green']}]CLEAN[/]")
            table.add_row(domain,
                          cell("A"), cell("AAAA"), cell("MX"),
                          cell("NS"), cell("TXT"), cell("CNAME"),
                          status_str)

        console.print(table)
        console.print(f"  [{C['dim']}]Scanned {stats['scanned']} records across {len(domains)} domains · "
                      f"{stats['changes']} changes · {stats['seizures']} seizure signals[/]")
        return stats


class HTTPMonitor:
    SEIZURE_REDIRECT = [".gov", ".mil", "seized", "justice.gov", "europol.europa.eu",
                        "interpol.int", "nca.police.uk"]

    def __init__(self, state: StateManager, notifier: Notifier,
                 scorer: RiskScorer, feed: EventFeed, proxies=None):
        self.state    = state
        self.notifier = notifier
        self.scorer   = scorer
        self.feed     = feed
        self.proxies  = proxies
        self.silent   = False

    def _fetch(self, domain: str) -> Optional[dict]:
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{domain}"
                r = requests.get(url, timeout=REQUEST_TIMEOUT,
                                 headers={"User-Agent": random.choice(USER_AGENTS)},
                                 verify=False, allow_redirects=True,
                                 proxies=self.proxies)
                body_hash = hashlib.sha256(r.content[:65536]).hexdigest()
                redirect_chain = [resp.url for resp in r.history] + [r.url]
                seized_in_body = any(kw in r.text.lower() for kw in SEIZURE_KEYWORDS)
                seized_redirect = any(p in r.url.lower() for p in self.SEIZURE_REDIRECT)
                return {
                    "status_code":    r.status_code,
                    "server":         r.headers.get("server", ""),
                    "body_hash":      body_hash,
                    "redirect_final": r.url,
                    "redirect_count": len(r.history),
                    "content_length": len(r.content),
                    "seized_body":    seized_in_body,
                    "seized_redirect":seized_redirect,
                    "scheme":         scheme,
                }
            except Exception:
                continue
        return None

    def check(self, domain: str) -> bool:
        current = self._fetch(domain)
        if not current:
            return False

        prev = self.state.get(domain)
        if not prev:
            self.state.set(domain, current)
            status_row("✦", C['green'], f"Baselined  {domain}",
                       f"HTTP {current['status_code']} {current['scheme'].upper()}")
            if current["seized_body"] or current["seized_redirect"]:
                score = self.scorer.add_signal(domain, "http_seizure_keyword",
                                               "Seizure keyword in body on first scan")
                if not self.silent:
                    alert_box("SEIZURE", domain, "Seizure content detected on first HTTP scan",
                              {"Status": str(current["status_code"]),
                               "Final URL": current["redirect_final"],
                               "Risk Score": str(score)})
            return True

        changed = False
        seized  = current.get("seized_body") or current.get("seized_redirect")

        if current["body_hash"] != prev.get("body_hash"):
            changed = True
            self.scorer.add_signal(domain, "http_body_change", "Body content hash changed")

        if current["status_code"] != prev.get("status_code"):
            changed = True

        if seized:
            score = self.scorer.add_signal(domain, "http_seizure_keyword",
                                           f"Redirect: {current['redirect_final']}")
            if current["seized_redirect"]:
                self.scorer.add_signal(domain, "http_redirect_gov")
            if not self.silent:
                alert_box("SEIZURE", domain, "HTTP seizure content detected",
                          {"Status": str(current["status_code"]),
                           "Final URL": current["redirect_final"],
                           "Body Hash": current["body_hash"][:16] + "...",
                           "Risk Score": str(self.scorer.get_score(domain))})
                self.notifier.send("SEIZURE", domain, "HTTP Seizure Detected",
                                   [{"name": "Status Code", "value": str(current["status_code"]), "inline": True},
                                    {"name": "Final URL", "value": current["redirect_final"], "inline": False}],
                                   score=self.scorer.get_score(domain))
            self.feed.add("http_seizure", domain, current)
        elif changed and not self.silent:
            alert_box("CHANGE", domain, "HTTP fingerprint changed",
                      {"Status": f"{prev.get('status_code')} → {current['status_code']}",
                       "Body": f"{prev.get('body_hash','')[:8]}... → {current['body_hash'][:8]}..."})

        self.state.set(domain, current)
        return changed

    def scan_all(self, domains: List[str]) -> Dict:
        stats = {"scanned": 0, "changes": 0}
        section_rule("HTTP FINGERPRINT MONITOR", C['yellow'])

        with Progress(SpinnerColumn(style=C['yellow']),
                      TextColumn("[bold white]{task.description}"),
                      BarColumn(style=C['dim'], complete_style=C['yellow']),
                      TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
                      TimeElapsedColumn(),
                      console=console) as prog:
            task = prog.add_task("Fingerprinting…", total=len(domains))
            with ThreadPoolExecutor(max_workers=HTTP_CONCURRENCY) as ex:
                futures = {ex.submit(self.check, d): d for d in domains}
                for fut in as_completed(futures):
                    stats["scanned"] += 1
                    if fut.result():
                        stats["changes"] += 1
                    prog.advance(task)

        console.print(f"  [{C['dim']}]Scanned {stats['scanned']} · {stats['changes']} changes[/]")
        return stats


class WHOISMonitor:
    def __init__(self, state: StateManager, notifier: Notifier,
                 scorer: RiskScorer, feed: EventFeed):
        self.state    = state
        self.notifier = notifier
        self.scorer   = scorer
        self.feed     = feed
        self.silent   = False

    def _query(self, domain: str) -> Optional[dict]:
        if not pywhois:
            return None
        try:
            w = pywhois.whois(domain)
            def clean(v):
                if isinstance(v, list): v = v[0]
                return str(v).lower().strip() if v else ""
            exp = w.expiration_date
            if isinstance(exp, list): exp = exp[0]
            return {
                "registrar":     clean(w.registrar),
                "org":           clean(w.org or w.registrant_name or ""),
                "nameservers":   sorted([ns.lower().strip() for ns in (w.name_servers or [])]),
                "status":        clean(w.status),
                "expiration":    str(exp.date()) if exp and hasattr(exp, "date") else "",
            }
        except Exception:
            return None

    def _seized(self, data: dict) -> List[str]:
        combined = json.dumps(data).lower()
        return [ind for ind in WHOIS_SEIZURE_INDICATORS if ind in combined]

    def check(self, domain: str) -> bool:
        current = self._query(domain)
        if not current:
            return False

        prev = self.state.get(domain)
        if not prev:
            self.state.set(domain, current)
            status_row("✦", C['green'], f"Baselined  {domain}",
                       f"WHOIS reg: {current['registrar'][:30] or 'unknown'}")
            indicators = self._seized(current)
            if indicators:
                score = self.scorer.add_signal(domain, "whois_seizure_indicator",
                                               f"On first scan: {', '.join(indicators)}")
                if not self.silent:
                    alert_box("SEIZURE", domain, "WHOIS seizure indicators on first scan",
                              {"Indicators": ", ".join(indicators), "Risk Score": str(score)})
            return True

        changed = False
        indicators = self._seized(current)

        if current.get("registrar") != prev.get("registrar"):
            changed = True
            self.scorer.add_signal(domain, "whois_registrar_change",
                                   f"{prev.get('registrar')} → {current.get('registrar')}")
        if sorted(current.get("nameservers", [])) != sorted(prev.get("nameservers", [])):
            changed = True
            self.scorer.add_signal(domain, "dns_ns_change")
        if indicators:
            self.scorer.add_signal(domain, "whois_seizure_indicator", ", ".join(indicators))

        if changed:
            if indicators and not self.silent:
                score = self.scorer.get_score(domain)
                alert_box("SEIZURE", domain, "WHOIS change — seizure indicators present",
                          {"Registrar": f"{prev.get('registrar')} → {current.get('registrar')}",
                           "Indicators": ", ".join(indicators), "Risk Score": str(score)})
                self.notifier.send("SEIZURE", domain, "WHOIS Seizure Indicators Detected",
                                   [{"name": "Registrar Change",
                                     "value": f"{prev.get('registrar')} → {current.get('registrar')}", "inline": False},
                                    {"name": "Seizure Indicators", "value": ", ".join(indicators), "inline": False}],
                                   score=score)
                self.feed.add("whois_seizure", domain, {"prev": prev, "current": current, "indicators": indicators})
            elif not self.silent:
                alert_box("CHANGE", domain, "WHOIS record changed",
                          {"Registrar": f"{prev.get('registrar','?')} → {current.get('registrar','?')}",
                           "Nameservers": " / ".join(current.get("nameservers", []))[:60]})

        self.state.set(domain, current)
        return changed

    def scan_all(self, domains: List[str]) -> Dict:
        stats = {"scanned": 0, "changes": 0}
        section_rule("WHOIS MONITOR", C['magenta'])
        with Progress(SpinnerColumn(style=C['magenta']),
                      TextColumn("[bold white]{task.description}"),
                      BarColumn(style=C['dim'], complete_style=C['magenta']),
                      TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("Querying WHOIS…", total=len(domains))
            with ThreadPoolExecutor(max_workers=WHOIS_CONCURRENCY) as ex:
                futures = {ex.submit(self.check, d): d for d in domains}
                for fut in as_completed(futures):
                    stats["scanned"] += 1
                    if fut.result(): stats["changes"] += 1
                    prog.advance(task)
        console.print(f"  [{C['dim']}]Scanned {stats['scanned']} · {stats['changes']} changes[/]")
        return stats


class SSLMonitor:
    """NEW — tracks certificate issuer, expiry, SANs, and fingerprint."""

    def __init__(self, state: StateManager, notifier: Notifier,
                 scorer: RiskScorer, feed: EventFeed):
        self.state    = state
        self.notifier = notifier
        self.scorer   = scorer
        self.feed     = feed
        self.silent   = False

    def _get_cert(self, domain: str, port: int = 443) -> Optional[dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    der  = ssock.getpeercert(binary_form=True)
            if not cert:
                return None
            fp = hashlib.sha256(der).hexdigest()[:32]
            # Expiry
            nb = cert.get("notAfter", "")
            try:
                exp = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.utcnow()).days
            except Exception:
                days_left = -1
            # Issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            issuer_org  = issuer_dict.get("organizationName", "").lower()
            issuer_cn   = issuer_dict.get("commonName", "").lower()
            # SANs
            sans = []
            for kind, value in cert.get("subjectAltName", []):
                if kind == "DNS":
                    sans.append(value)
            return {
                "fingerprint": fp,
                "issuer_org":  issuer_org,
                "issuer_cn":   issuer_cn,
                "days_left":   days_left,
                "expiry":      nb,
                "sans":        sorted(sans),
            }
        except Exception:
            return None

    def _is_le_ca(self, cert: dict) -> bool:
        combined = (cert.get("issuer_org","") + " " + cert.get("issuer_cn","")).lower()
        return any(kw in combined for kw in LE_CA_ORGS)

    def check(self, domain: str) -> bool:
        current = self._get_cert(domain)
        if not current:
            return False

        prev = self.state.get(domain)
        if not prev:
            self.state.set(domain, current)
            status_row("✦", C['green'], f"Baselined  {domain}",
                       f"SSL ·  {current['days_left']}d left  ·  {current['issuer_cn'][:25]}")
            if self._is_le_ca(current):
                score = self.scorer.add_signal(domain, "ssl_le_ca",
                                               f"LE CA: {current['issuer_org']}")
                if not self.silent:
                    alert_box("SEIZURE", domain,
                              "SSL certificate issued by law-enforcement-associated CA",
                              {"Issuer": current["issuer_org"] or current["issuer_cn"],
                               "Days Left": str(current["days_left"]),
                               "Fingerprint": current["fingerprint"],
                               "Risk Score": str(score)})
            return True

        changed = False

        if current["fingerprint"] != prev.get("fingerprint"):
            changed = True
            # Issuer changed?
            if current["issuer_org"] != prev.get("issuer_org"):
                self.scorer.add_signal(domain, "ssl_issuer_change",
                                       f"{prev.get('issuer_org')} → {current['issuer_org']}")
            # Days dramatically dropped?
            prev_days = prev.get("days_left", 9999)
            if current["days_left"] < prev_days - 30:
                self.scorer.add_signal(domain, "ssl_expiry_drop",
                                       f"{prev_days}d → {current['days_left']}d")
            if self._is_le_ca(current):
                score = self.scorer.add_signal(domain, "ssl_le_ca",
                                               f"New LE CA: {current['issuer_org']}")
                if not self.silent:
                    alert_box("SEIZURE", domain,
                              "SSL cert changed — new issuer is law-enforcement CA",
                              {"Old Issuer": prev.get("issuer_org", "?"),
                               "New Issuer": current["issuer_org"],
                               "Days Left":  str(current["days_left"]),
                               "Risk Score": str(self.scorer.get_score(domain))})
                    self.notifier.send("SEIZURE", domain, "SSL Certificate — LE CA Detected",
                                       [{"name": "Previous Issuer", "value": prev.get("issuer_org","?"), "inline": True},
                                        {"name": "New Issuer", "value": current["issuer_org"], "inline": True},
                                        {"name": "Fingerprint", "value": current["fingerprint"], "inline": False}],
                                       score=self.scorer.get_score(domain))
                    self.feed.add("ssl_le_ca", domain, {"prev": prev, "current": current})
            elif not self.silent:
                alert_box("SSL", domain, "SSL certificate rotated",
                          {"Old Issuer": prev.get("issuer_org","?"),
                           "New Issuer": current["issuer_org"],
                           "Days Left":  str(current["days_left"])})

        self.state.set(domain, current)
        return changed

    def scan_all(self, domains: List[str]) -> Dict:
        stats = {"scanned": 0, "changes": 0}
        section_rule("SSL / TLS CERTIFICATE MONITOR", C['magenta'])
        with Progress(SpinnerColumn(style=C['magenta']),
                      TextColumn("[bold white]{task.description}"),
                      BarColumn(style=C['dim'], complete_style=C['magenta']),
                      TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("Checking certs…", total=len(domains))
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(self.check, d): d for d in domains}
                for fut in as_completed(futures):
                    stats["scanned"] += 1
                    if fut.result(): stats["changes"] += 1
                    prog.advance(task)
        console.print(f"  [{C['dim']}]Scanned {stats['scanned']} · {stats['changes']} changes[/]")
        return stats


class IPMonitor:
    def __init__(self, state: StateManager, notifier: Notifier,
                 scorer: RiskScorer, feed: EventFeed):
        self.state    = state
        self.notifier = notifier
        self.scorer   = scorer
        self.feed     = feed
        self.silent   = False
        self._session = requests.Session()

    def _resolve_ips(self, domain: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=DNS_TIMEOUT)
            return sorted(r.to_text() for r in answers)
        except Exception:
            return []

    def _rdns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0].lower()
        except Exception:
            return ""

    def _is_le_rdns(self, rdns: str) -> bool:
        le_patterns = ["doj.gov", "fbi.gov", "justice.gov", "seized", "europol", "nca.police", "gov"]
        return any(p in rdns for p in le_patterns)

    def check(self, domain: str) -> bool:
        ips = self._resolve_ips(domain)
        if not ips:
            return False

        rdns_map = {ip: self._rdns(ip) for ip in ips}
        prev = self.state.get(domain) or {}
        prev_ips = prev.get("ips", [])

        if ips == prev_ips:
            return False

        changed = True
        added   = [ip for ip in ips if ip not in prev_ips]
        le_ips  = [(ip, rdns_map[ip]) for ip in added if self._is_le_rdns(rdns_map[ip])]

        score = self.scorer.add_signal(domain, "ip_change", f"IPs: {', '.join(added)}")
        if le_ips:
            score = self.scorer.add_signal(domain, "ip_le_rdns",
                                           ", ".join(f"{ip} ({rdns})" for ip, rdns in le_ips))

        self.state.set(domain, {"ips": ips, "rdns": rdns_map})

        if not prev_ips:
            status_row("✦", C['green'], f"Baselined  {domain}", f"IPs: {', '.join(ips)}")
            return True

        if le_ips and not self.silent:
            alert_box("SEIZURE", domain, "IP changed to law-enforcement infrastructure",
                      {"New IPs": ", ".join(f"{ip} [{rdns}]" for ip, rdns in le_ips),
                       "Risk Score": str(score)})
            self.notifier.send("SEIZURE", domain, "IP → Law Enforcement Infrastructure",
                               [{"name": "New IPs", "value": ", ".join(ip for ip, _ in le_ips), "inline": False},
                                {"name": "rDNS", "value": ", ".join(rdns for _, rdns in le_ips), "inline": False}],
                               score=score)
            self.feed.add("ip_le", domain, {"new_ips": ips, "prev_ips": prev_ips, "le_ips": le_ips})
        elif not self.silent:
            alert_box("CHANGE", domain, "IP address changed",
                      {"Previous": ", ".join(prev_ips), "New": ", ".join(ips)})

        return True

    def scan_all(self, domains: List[str]) -> Dict:
        stats = {"scanned": 0, "changes": 0}
        section_rule("IP ADDRESS MONITOR", C['cyan'])
        with Progress(SpinnerColumn(style=C['cyan']),
                      TextColumn("[bold white]{task.description}"),
                      BarColumn(style=C['dim'], complete_style=C['cyan']),
                      TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("Resolving IPs…", total=len(domains))
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(self.check, d): d for d in domains}
                for fut in as_completed(futures):
                    stats["scanned"] += 1
                    if fut.result(): stats["changes"] += 1
                    prog.advance(task)
        console.print(f"  [{C['dim']}]Scanned {stats['scanned']} · {stats['changes']} changes[/]")
        return stats


# ══════════════════════════════════════════════════════════════════════
# RISK SUMMARY PRINTER
# ══════════════════════════════════════════════════════════════════════

def print_risk_summary(scorer: RiskScorer, domains: List[str]):
    section_rule("RISK SCORE SUMMARY", C['orange'])
    table = Table(show_header=True, header_style=f"bold {C['orange']}", box=rich_box.SIMPLE_HEAVY,
                  border_style=C['dim'], padding=(0, 1))
    table.add_column("Domain", style="white", min_width=28)
    table.add_column("Risk Score", min_width=28)
    table.add_column("Level", justify="center", min_width=10)
    table.add_column("Top Signal", min_width=24)

    for domain in sorted(domains, key=lambda d: -scorer.get_score(d)):
        score   = scorer.get_score(domain)
        signals = scorer.get_signals(domain)
        top_sig = signals[-1]["signal"].replace("_", " ").upper() if signals else "—"
        if score >= 70:
            level_str = f"[bold {C['red']}]CRITICAL[/]"
        elif score >= 40:
            level_str = f"[bold {C['yellow']}]ELEVATED[/]"
        elif score > 0:
            level_str = f"[{C['cyan']}]LOW[/]"
        else:
            level_str = f"[{C['dim']}]NONE[/]"
        table.add_row(domain, risk_bar(score), level_str, f"[dim]{top_sig}[/dim]")

    console.print(table)


# ══════════════════════════════════════════════════════════════════════
# MAIN ENGINE
# ══════════════════════════════════════════════════════════════════════

class ZeroXWatch:
    def __init__(self, enable_dns=True, enable_http=True, enable_whois=True,
                 enable_ip=True, enable_ssl=True, proxy=None):
        self.enable_dns   = enable_dns
        self.enable_http  = enable_http
        self.enable_whois = enable_whois
        self.enable_ip    = enable_ip
        self.enable_ssl   = enable_ssl
        self.running      = True

        proxies = {"http": proxy, "https": proxy} if proxy else None

        self.notifier = Notifier()
        self.scorer   = RiskScorer()
        self.feed     = EventFeed()

        self.dns_state   = StateManager(STATE_FILE)
        self.http_state  = StateManager(HTTP_STATE_FILE)
        self.whois_state = StateManager(WHOIS_STATE_FILE)
        self.ip_state    = StateManager(IP_STATE_FILE)
        self.ssl_state   = StateManager(SSL_STATE_FILE)

        self.dns_mon   = DNSMonitor(self.dns_state,   self.notifier, self.scorer, self.feed)
        self.http_mon  = HTTPMonitor(self.http_state,  self.notifier, self.scorer, self.feed, proxies)
        self.whois_mon = WHOISMonitor(self.whois_state,self.notifier, self.scorer, self.feed)
        self.ip_mon    = IPMonitor(self.ip_state,      self.notifier, self.scorer, self.feed)
        self.ssl_mon   = SSLMonitor(self.ssl_state,    self.notifier, self.scorer, self.feed)

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, sig, frame):
        console.print()
        console.print(Rule(f"[{C['red']}] Shutting down 0xWatch…[/]", style=C['red']))
        self.running = False
        for st in [self.dns_state, self.http_state, self.whois_state,
                   self.ip_state, self.ssl_state]:
            try: st.save()
            except Exception: pass
        console.print(f"  [{C['green']}]✓ State saved. Goodbye.[/]")
        sys.exit(0)

    def _set_silent(self, s: bool):
        for m in [self.dns_mon, self.http_mon, self.whois_mon,
                  self.ip_mon, self.ssl_mon]:
            m.silent = s

    def _load_all(self):
        for st in [self.dns_state, self.http_state, self.whois_state,
                   self.ip_state, self.ssl_state]:
            st.load()

    def _save_all(self):
        for st in [self.dns_state, self.http_state, self.whois_state,
                   self.ip_state, self.ssl_state]:
            st.save()

    def _print_status_header(self, domains, onions, scan_no, silent, total_silent):
        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        mode_str = (f"[bold {C['yellow']}]SILENT {scan_no}/{total_silent}[/]"
                    if silent else f"[bold {C['green']}]LIVE[/]")

        console.print()
        console.print(Rule(
            f"[bold {C['cyan']}]  SCAN #{scan_no:04d}[/]  [{C['dim']}]{ts}[/]  {mode_str}",
            style=C['cyan']
        ))

        # Monitor badges
        badges = [
            monitor_badge("DNS",   self.enable_dns),
            monitor_badge("HTTP",  self.enable_http),
            monitor_badge("WHOIS", self.enable_whois),
            monitor_badge("IP",    self.enable_ip),
            monitor_badge("SSL",   self.enable_ssl),
        ]
        console.print("  " + "  ".join(badges))

        # Stats row
        top5 = self.scorer.top_domains(3)
        top_str = "  ".join(
            f"[{C['dim']}]{d}[/] {risk_bar(s, 8)}" for d, s in top5
        ) if top5 else f"[{C['dim']}]No signals yet[/]"
        console.print(f"\n  [{C['dim']}]Monitoring:[/] "
                      f"[bold {C['cyan']}]{len(domains)}[/] clearnet  "
                      f"[bold {C['magenta']}]{len(onions)}[/] onion")
        console.print(f"  [{C['dim']}]Top risk:[/]  {top_str}")
        console.print()

    def run(self, site_manager: SiteManager, silent_cycles: int = 1):
        self._load_all()
        scan_count = 0

        while self.running:
            scan_count += 1
            is_silent  = scan_count <= silent_cycles

            # Hot-reload sites
            site_manager.reload()
            domains = site_manager.domains
            onions  = site_manager.onion_sites

            self._set_silent(is_silent)
            self._print_status_header(domains, onions, scan_count, is_silent, silent_cycles)

            if not domains:
                console.print(f"  [{C['yellow']}]⚠  No clearnet domains in {SITES_FILE}[/]")
                console.print(f"  [{C['dim']}]Add domains via the Sites menu (option 4)[/]")
            else:
                if self.enable_dns:
                    self.dns_mon.scan_all(domains)
                    self.dns_state.save()
                if self.enable_http:
                    self.http_mon.scan_all(domains)
                    self.http_state.save()
                if self.enable_whois:
                    self.whois_mon.scan_all(domains)
                    self.whois_state.save()
                if self.enable_ip:
                    self.ip_mon.scan_all(domains)
                    self.ip_state.save()
                if self.enable_ssl:
                    self.ssl_mon.scan_all(domains)
                    self.ssl_state.save()
                print_risk_summary(self.scorer, domains)

            # Cycle complete
            console.print()
            console.print(Rule(
                f"[bold {C['green']}]  Cycle #{scan_count:04d} complete  ·  "
                f"sleeping {SCAN_INTERVAL}s  [/]",
                style=C['green']
            ))
            console.print()
            time.sleep(SCAN_INTERVAL)


# ══════════════════════════════════════════════════════════════════════
# MENUS
# ══════════════════════════════════════════════════════════════════════

def startup_menu(site_manager: SiteManager, scorer: RiskScorer) -> dict:
    print_banner()

    # Quick stats
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column(justify="right", style=C['dim'])
    stats_table.add_column(style=f"bold {C['cyan']}")
    stats_table.add_row("Clearnet domains",  str(len(site_manager.domains)))
    stats_table.add_row("Onion sites",       str(len(site_manager.onion_sites)))
    stats_table.add_row("Event feed",        f"{EVENT_FEED_FILE}" if EVENT_FEED_FILE.exists() else "empty")
    stats_table.add_row("Risk scores",       f"{len(scorer.scores)} domains tracked")
    console.print(Panel(stats_table, title=f"[{C['dim']}]System Status[/]",
                        border_style=C['dim'], padding=(0, 2)))
    console.print()

    menu_items = [
        ("1", C['green'],   "Start monitoring",        "alerts active immediately"),
        ("2", C['yellow'],  "Start silent mode",       "build baseline, no alerts"),
        ("3", C['cyan'],    "Reset state & start",     "wipe all state files"),
        ("4", C['white'],   "Manage sites",            "add / remove / list domains"),
        ("5", C['magenta'], "Toggle monitors",         "enable/disable each monitor"),
        ("6", C['orange'],  "View risk scores",        "current domain risk table"),
        ("7", C['dim'],     "Exit",                    ""),
    ]
    for num, color, label, hint in menu_items:
        hint_str = f"  [dim]{hint}[/dim]" if hint else ""
        console.print(f"  [{color}]{num}.[/]  [{C['white']}]{label}[/]{hint_str}")
    console.print()

    while True:
        try:
            choice = input("  Select [1-7]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return {"action": "exit"}

        if choice == "1": return {"action": "run", "silent": 0}
        if choice == "2":
            try:
                n = int(input("  Silent cycles [1]: ").strip() or "1")
            except Exception:
                n = 1
            return {"action": "run", "silent": max(1, n)}
        if choice == "3": return {"action": "reset"}
        if choice == "4": return {"action": "sites"}
        if choice == "5": return {"action": "toggle"}
        if choice == "6": return {"action": "scores"}
        if choice == "7": return {"action": "exit"}
        console.print(f"  [{C['red']}]Invalid choice[/]")


def sites_menu(site_manager: SiteManager):
    while True:
        print_banner()
        section_rule("MONITORED SITES", C['cyan'])
        console.print(f"  [{C['cyan']}]{len(site_manager.domains)}[/] clearnet  "
                      f"[{C['magenta']}]{len(site_manager.onion_sites)}[/] onion  "
                      f"[{C['dim']}]source: {SITES_FILE}[/]")
        console.print()
        console.print(f"  [{C['green']}]1.[/]  Add site(s)")
        console.print(f"  [{C['red']}]2.[/]  Remove site")
        console.print(f"  [{C['cyan']}]3.[/]  List clearnet domains")
        console.print(f"  [{C['magenta']}]4.[/]  List onion sites")
        console.print(f"  [{C['dim']}]5.[/]  Back")
        console.print()
        try:
            ch = input("  Select [1-5]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        if ch == "1":
            raw = input("  Site(s) — comma or space separated: ").strip()
            for s in re.split(r"[,\s]+", raw):
                if not s: continue
                kind, ok = site_manager.add(s)
                if kind == "invalid":
                    console.print(f"  [{C['red']}]✗ Invalid: {s}[/]")
                elif ok:
                    console.print(f"  [{C['green']}]✓ Added ({kind}): {s}[/]")
                else:
                    console.print(f"  [{C['yellow']}]⚠ Already monitored: {s}[/]")

        elif ch == "2":
            s = input("  Site to remove: ").strip()
            kind, ok = site_manager.remove(s)
            if ok:
                console.print(f"  [{C['red']}]✓ Removed: {s}[/]")
            else:
                console.print(f"  [{C['yellow']}]Not found: {s}[/]")

        elif ch == "3":
            section_rule(f"Clearnet Domains ({len(site_manager.domains)})", C['cyan'])
            for i, d in enumerate(site_manager.domains, 1):
                console.print(f"  [{C['dim']}]{i:>3}.[/]  {d}")

        elif ch == "4":
            section_rule(f"Onion Sites ({len(site_manager.onion_sites)})", C['magenta'])
            for i, d in enumerate(site_manager.onion_sites, 1):
                console.print(f"  [{C['dim']}]{i:>3}.[/]  {d}")

        elif ch == "5":
            return


def toggle_menu(flags: dict) -> dict:
    labels = {
        "enable_dns":   ("DNS",   C['cyan']),
        "enable_http":  ("HTTP",  C['yellow']),
        "enable_whois": ("WHOIS", C['magenta']),
        "enable_ip":    ("IP",    C['cyan']),
        "enable_ssl":   ("SSL",   C['magenta']),
    }
    keys = list(labels.keys())
    while True:
        print_banner()
        section_rule("TOGGLE MONITORS", C['white'])
        for i, k in enumerate(keys, 1):
            name, color = labels[k]
            state = f"[bold {C['green']}]ON [/]" if flags[k] else f"[bold {C['red']}]OFF[/]"
            console.print(f"  [{color}]{i}.[/]  [{C['white']}]{name:<8}[/]  {state}")
        console.print(f"  [{C['dim']}]6.[/]  Back")
        console.print()
        try:
            ch = input("  Toggle [1-6]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return flags
        if ch in ("1","2","3","4","5"):
            k = keys[int(ch)-1]
            flags[k] = not flags[k]
            name, _ = labels[k]
            console.print(f"  [{C['yellow']}]→ {name} is now {'ON' if flags[k] else 'OFF'}[/]")
        elif ch == "6":
            return flags


def scores_menu(scorer: RiskScorer, site_manager: SiteManager):
    print_banner()
    print_risk_summary(scorer, site_manager.domains)
    input(f"\n  [{C['dim']}]Press Enter to return…[/] ")


def reset_state():
    files = [STATE_FILE, HTTP_STATE_FILE, WHOIS_STATE_FILE,
             IP_STATE_FILE, SSL_STATE_FILE, SCORE_FILE, EVENT_FEED_FILE]
    for f in files:
        if f.exists():
            f.unlink()
    console.print(f"  [{C['green']}]✓ All state files cleared.[/]")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(prog="0xwatch",
                                     description=f"{TOOL_NAME} — {TOOL_SUBTITLE}")
    parser.add_argument("--no-dns",   action="store_true")
    parser.add_argument("--no-http",  action="store_true")
    parser.add_argument("--no-whois", action="store_true")
    parser.add_argument("--no-ip",    action="store_true")
    parser.add_argument("--no-ssl",   action="store_true")
    parser.add_argument("--silent",   type=int, default=None,
                        help="Silent cycles before firing alerts")
    parser.add_argument("--proxy",    default=os.getenv("CLEARNET_PROXY",""),
                        help="SOCKS5 proxy (socks5h://user:pass@host:port)")
    parser.add_argument("--interval", type=int, default=None,
                        help="Override scan interval in seconds")
    args = parser.parse_args()

    global SCAN_INTERVAL
    if args.interval:
        SCAN_INTERVAL = args.interval

    site_manager = SiteManager()
    scorer       = RiskScorer()

    flags = {
        "enable_dns":   not args.no_dns,
        "enable_http":  not args.no_http,
        "enable_whois": not args.no_whois,
        "enable_ip":    not args.no_ip,
        "enable_ssl":   not args.no_ssl,
    }

    # CLI quick-start
    if args.silent is not None:
        engine = ZeroXWatch(**flags, proxy=args.proxy)
        engine.run(site_manager, silent_cycles=args.silent)
        return

    # Interactive menu loop
    while True:
        result = startup_menu(site_manager, scorer)
        action = result["action"]

        if action == "exit":
            console.print(f"\n  [{C['dim']}]Goodbye.[/]\n")
            sys.exit(0)

        elif action == "sites":
            sites_menu(site_manager)

        elif action == "toggle":
            flags = toggle_menu(flags)

        elif action == "scores":
            scores_menu(scorer, site_manager)

        elif action == "reset":
            reset_state()
            engine = ZeroXWatch(**flags, proxy=args.proxy)
            engine.run(site_manager, silent_cycles=1)

        elif action == "run":
            engine = ZeroXWatch(**flags, proxy=args.proxy)
            engine.run(site_manager, silent_cycles=result.get("silent", 1))


if __name__ == "__main__":
    main()
