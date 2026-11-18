"""
Seed the database with realistic demo data so the dashboard is viewable
without running live queries (useful for screenshots and for environments
with no outbound internet).

    python3 seed_demo.py

The data below is fabricated sample output in the exact shape the collectors
produce. It does not come from scanning any real domain.
"""

import database as db


def demo_scan(scanned_at, subdomains, ports, emails):
    sub_list = ["www.example.com", "mail.example.com", "api.example.com",
                "dev.example.com", "vpn.example.com", "shop.example.com",
                "blog.example.com", "staging.example.com"][:subdomains]
    port_list = [80, 443, 22, 8080, 3306, 25][:ports]
    email_list = ["info@example.com", "admin@example.com",
                  "security@example.com", "careers@example.com"][:emails]
    return {
        "domain": "example.com",
        "scanned_at": scanned_at,
        "whois": {"ok": True, "error": None, "data": {
            "registrar": "IANA Reserved Registrar",
            "created": "1995-08-14", "expires": "2027-08-13",
            "updated": "2025-08-14", "registrant_org": "Example Org",
            "country": "US",
            "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
            "emails": email_list,
        }},
        "crtsh": {"ok": True, "error": None,
                  "data": {"count": len(sub_list), "subdomains": sub_list}},
        "dns": {"ok": True, "error": None, "data": {
            "primary_ips": ["93.184.216.34"],
            "records": {
                "A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                "MX": ["10 mail.example.com."], "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
                "TXT": ["v=spf1 -all"],
            }}},
        "shodan": {"ok": True, "error": None, "data": {
            "ip": "93.184.216.34", "org": "Example Hosting", "os": None,
            "ports": port_list,
            "services": [{"port": p, "transport": "tcp",
                          "product": {80: "nginx", 443: "nginx", 22: "OpenSSH",
                                      8080: "Jetty", 3306: "MySQL", 25: "Postfix"}.get(p)}
                         for p in port_list],
        }},
        "emails": {"ok": True, "error": None,
                   "data": {"count": len(email_list), "emails": email_list}},
        "summary": {"subdomains": len(sub_list), "open_ports": len(port_list),
                    "emails": len(email_list),
                    "dns_records": 6},
    }


def main():
    db.init_db()
    # Three scans over time so the trend chart shows growth (new subdomains and
    # a newly exposed port appearing between scans — the kind of drift a threat
    # intel analyst watches for).
    db.save_scan(demo_scan("2026-09-01T09:00:00Z", subdomains=4, ports=3, emails=2))
    db.save_scan(demo_scan("2026-10-01T09:00:00Z", subdomains=6, ports=4, emails=3))
    db.save_scan(demo_scan("2026-11-01T09:00:00Z", subdomains=8, ports=6, emails=4))
    print("Seeded demo target 'example.com' with 3 scans. Start the app with: python3 app.py")


if __name__ == "__main__":
    main()
