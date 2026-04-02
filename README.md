# 0xWatch — Domain Seizure Intelligence Platform

```
  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ██╔═████╗╚██╗██╔╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ██║██╔██║ ╚███╔╝ ██║ █╗ ██║███████║   ██║   ██║     ███████║
 ████╔╝██║ ██╔██╗ ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

**v1.0.0** — Professional domain monitoring & law-enforcement seizure detection

---

## Installation

```bash
pip install -r requirements.txt

# Configure alerts (optional)
cp env.example .env
nano .env
```

## Usage

```bash
# Interactive menu
python 0xwatch.py

# Direct start — silent baseline then live monitoring
python 0xwatch.py --silent 1

# Disable specific monitors
python 0xwatch.py --no-whois --no-onion

# Custom scan interval
python 0xwatch.py --interval 30

# With proxy
python 0xwatch.py --proxy socks5h://127.0.0.1:9050

# All flags
python 0xwatch.py --help
```

---

## Monitors

| Monitor | What It Detects |
|---------|----------------|
| **DNS** | A, AAAA, MX, NS, TXT, CNAME changes · seizure keyword patterns in records |
| **HTTP** | Body hash changes · status code shifts · redirect-to-.gov patterns · seizure keywords in page content |
| **WHOIS** | Registrar changes · nameserver mutations · seizure indicator strings in org/registrar fields |
| **IP** | A/AAAA record IP changes · reverse DNS lookup · law-enforcement rDNS patterns (doj.gov, fbi.gov…) |
| **SSL** | Certificate fingerprint · issuer org/CN changes · expiry anomalies · law-enforcement CA detection |

---

## Risk Scoring

0xWatch aggregates signals from all monitors into a **0–100 risk score** per domain:

| Signal | Points |
|--------|--------|
| DNS seizure keyword | 50 |
| HTTP seizure content | 45 |
| WHOIS seizure indicator | 40 |
| HTTP redirect to .gov | 40 |
| SSL — LE CA issuer | 35 |
| IP — LE rDNS | 30 |
| SSL expiry anomaly | 25 |
| SSL issuer change | 20 |
| IP address change | 10 |
| DNS A record change | 12 |
| DNS NS change | 15 |
| HTTP body change | 15 |
| WHOIS registrar change | 10 |

Alerts fire to Discord/Telegram **only when risk score ≥ 40** — eliminating false-positive noise from minor changes.

---

## Alerts

Configure Discord and/or Telegram in `.env`:

```env
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
TELEGRAM_BOT_TOKEN=bot123456:ABC...
TELEGRAM_CHAT_ID=-1001234567890
```

Alert levels: `SEIZURE` (red) · `CHANGE` (yellow) · `SSL` (purple) · `NEW` (green)

---

## State Files

| File | Contents |
|------|----------|
| `0xwatch_dns.json` | DNS record history per domain |
| `0xwatch_http.json` | HTTP fingerprints (body hash, status, headers) |
| `0xwatch_whois.json` | WHOIS snapshots |
| `0xwatch_ip.json` | IP addresses + rDNS |
| `0xwatch_ssl.json` | SSL cert fingerprints + issuer + expiry |
| `0xwatch_scores.json` | Risk scores + signal history |
| `0xwatch_events.json` | Event feed (last 1000 events) |
| `monitored_sites.json` | Domain/onion list (hot-reloaded each cycle) |

---

## Adding Sites

Via interactive menu (option 4), or edit `monitored_sites.json` directly:

```json
{
  "clearnet": ["example.com", "target.net"],
  "onion":    ["abc123def456.onion"]
}
```

The file is **hot-reloaded** every scan cycle — no restart needed.

---

## Legal Notice

0xWatch is a passive monitoring tool intended for threat intelligence research, cybersecurity operations, and authorized domain surveillance. Use responsibly and in compliance with applicable laws.
