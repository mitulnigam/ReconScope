"""
OSINT collectors
----------------
Each collector queries ONE public source and returns a uniform dict:

    {"ok": bool, "data": <structured result>, "error": <str or None>}

Every collector fails soft: a network error or missing dependency returns
ok=False with an error message rather than raising, so one dead source never
takes down the whole scan.

All sources here are PUBLIC (certificate transparency, WHOIS, DNS, Shodan).
Only run this against domains you own or are explicitly authorized to assess.
"""

import os
import re
import socket
import datetime

import requests

HTTP_TIMEOUT = 15
CRTSH_TIMEOUT = 40  # crt.sh is frequently slow; give it room before giving up
USER_AGENT = "osint-dashboard/1.0 (authorized security assessment)"


def _result(ok, data=None, error=None):
    return {"ok": ok, "data": data if data is not None else {}, "error": error}


# ---------------------------------------------------------------------------
# WHOIS — registrar, key dates, name servers, registrant org/emails
# ---------------------------------------------------------------------------
def whois_lookup(domain):
    try:
        import whois  # python-whois
    except ImportError:
        return _result(False, error="python-whois not installed")

    try:
        w = whois.whois(domain)
    except Exception as e:
        return _result(False, error=f"WHOIS query failed: {e}")

    def first(value):
        # python-whois returns some fields as a list; take the first entry.
        if isinstance(value, (list, tuple)):
            return value[0] if value else None
        return value

    def iso(value):
        value = first(value)
        if isinstance(value, datetime.datetime):
            return value.date().isoformat()
        return str(value) if value else None

    emails = w.emails or []
    if isinstance(emails, str):
        emails = [emails]

    data = {
        "registrar": first(w.registrar),
        "created": iso(w.creation_date),
        "expires": iso(w.expiration_date),
        "updated": iso(w.updated_date),
        "name_servers": sorted({ns.lower() for ns in (w.name_servers or [])}),
        "registrant_org": first(w.get("org")) if hasattr(w, "get") else None,
        "emails": sorted(set(emails)),
        "country": first(w.get("country")) if hasattr(w, "get") else None,
    }
    return _result(True, data)


# ---------------------------------------------------------------------------
# crt.sh — subdomains discovered via Certificate Transparency logs
# ---------------------------------------------------------------------------
def crtsh_subdomains(domain, retries=1):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    last_err = None
    for _ in range(retries + 1):
        try:
            resp = requests.get(url, timeout=CRTSH_TIMEOUT,
                                headers={"User-Agent": USER_AGENT})
            resp.raise_for_status()
            if not resp.text.strip():
                # crt.sh sometimes returns an empty 200 when overloaded.
                last_err = "crt.sh returned an empty response"
                continue
            rows = resp.json()
        except Exception as e:
            last_err = str(e)
            continue

        names = set()
        for row in rows:
            # 'name_value' may hold several names separated by newlines.
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    names.add(name)

        subdomains = sorted(names)
        return _result(True, {"count": len(subdomains), "subdomains": subdomains})

    return _result(False, error=f"crt.sh query failed: {last_err}")


# ---------------------------------------------------------------------------
# DNS — common record types
# ---------------------------------------------------------------------------
def dns_records(domain):
    try:
        import dns.resolver
    except ImportError:
        return _result(False, error="dnspython not installed")

    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = HTTP_TIMEOUT
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = sorted(r.to_text().strip('"') for r in answers)
        except Exception:
            records[rtype] = []

    primary_ips = records.get("A", [])
    return _result(True, {"records": records, "primary_ips": primary_ips})


# ---------------------------------------------------------------------------
# Shodan — exposed ports/services for the domain's primary IP (optional)
# Requires a SHODAN_API_KEY; skipped gracefully if absent.
# ---------------------------------------------------------------------------
def shodan_lookup(domain, api_key=None):
    if not api_key:
        return _result(False, error="No Shodan API key set (SHODAN_API_KEY)")

    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return _result(False, error=f"Could not resolve {domain}: {e}")

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT,
                            headers={"User-Agent": USER_AGENT})
        if resp.status_code == 404:
            return _result(True, {"ip": ip, "ports": [], "services": []})
        resp.raise_for_status()
        host = resp.json()
    except Exception as e:
        return _result(False, error=f"Shodan query failed: {e}")

    services = []
    for item in host.get("data", []):
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product") or item.get("_shodan", {}).get("module"),
        })
    data = {
        "ip": ip,
        "org": host.get("org"),
        "os": host.get("os"),
        "ports": sorted(host.get("ports", [])),
        "services": services,
    }
    return _result(True, data)


# ---------------------------------------------------------------------------
# Email harvest — addresses publicly visible on the site's homepage
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def harvest_emails(domain):
    found = set()
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=HTTP_TIMEOUT,
                                headers={"User-Agent": USER_AGENT})
            for match in EMAIL_RE.findall(resp.text):
                found.add(match.lower())
            break  # succeeded on this scheme; no need to try the other
        except Exception:
            continue

    emails = sorted(e for e in found if e.endswith(domain) or domain in e)
    return _result(True, {"count": len(emails), "emails": emails})


# ---------------------------------------------------------------------------
# Orchestrator — run every collector and assemble one scan result
# ---------------------------------------------------------------------------
def run_scan(domain, shodan_api_key=None):
    """Run all collectors against a domain and return a combined result dict."""
    # Normalize: drop any scheme and path, keep just the host.
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].strip()

    scan = {
        "domain": domain,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "whois": whois_lookup(domain),
        "crtsh": crtsh_subdomains(domain),
        "dns": dns_records(domain),
        "shodan": shodan_lookup(domain, shodan_api_key),
        "emails": harvest_emails(domain),
    }

    # Headline counts, used for the dashboard trend charts.
    scan["summary"] = {
        "subdomains": scan["crtsh"]["data"].get("count", 0) if scan["crtsh"]["ok"] else 0,
        "open_ports": len(scan["shodan"]["data"].get("ports", [])) if scan["shodan"]["ok"] else 0,
        "emails": scan["emails"]["data"].get("count", 0) if scan["emails"]["ok"] else 0,
        "dns_records": sum(len(v) for v in scan["dns"]["data"].get("records", {}).values()) if scan["dns"]["ok"] else 0,
    }
    return scan


# ---------------------------------------------------------------------------
# Terminal diagnostic: run each collector against a domain and print whether
# it succeeded and, if not, the exact error. Bypasses the web UI entirely.
#   python3 collectors.py owasp-juice.shop
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"Scanning {target} ...\n")
    out = run_scan(target, shodan_api_key=os.environ.get("SHODAN_API_KEY"))

    for source in ("whois", "crtsh", "dns", "shodan", "emails"):
        r = out[source]
        state = "OK  " if r["ok"] else "FAIL"
        note = "" if r["ok"] else f"  -> {r['error']}"
        print(f"  [{state}] {source}{note}")

    print("\nSummary counts:")
    print(json.dumps(out["summary"], indent=2))
