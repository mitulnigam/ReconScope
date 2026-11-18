"""
OSINT Dashboard — Flask application.

Routes:
  GET  /                 dashboard: scan form + table of known targets
  POST /scan             run a scan on a submitted domain, then redirect
  GET  /target/<id>      detail view for one target (findings + charts)
  GET  /api/target/<id>/trends   JSON time-series for the Chart.js graphs

Run:
  python3 app.py            then open http://127.0.0.1:5000

For authorized use only. Query domains you own or are permitted to assess.
"""

import os

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, abort)

import database as db
import collectors

app = Flask(__name__)
app.secret_key = os.environ.get("OSINT_SECRET", "dev-key-change-me")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

db.init_db()


@app.route("/")
def index():
    targets = db.list_targets()
    return render_template("index.html", targets=targets)


@app.route("/scan", methods=["POST"])
def scan():
    domain = (request.form.get("domain") or "").strip()
    if not domain:
        flash("Please enter a domain.", "error")
        return redirect(url_for("index"))

    try:
        result = collectors.run_scan(domain, shodan_api_key=SHODAN_API_KEY)
        db.save_scan(result)
        target_id = db.get_or_create_target(result["domain"])
        flash(f"Scan complete for {result['domain']}.", "ok")
        return redirect(url_for("target", target_id=target_id))
    except Exception as e:
        flash(f"Scan failed: {e}", "error")
        return redirect(url_for("index"))


@app.route("/target/<int:target_id>")
def target(target_id):
    t = db.get_target(target_id)
    if not t:
        abort(404)
    latest = db.get_latest_scan(target_id)
    scan_data = db.scan_results(latest) if latest else None
    scan_count = len(db.get_scans_for_target(target_id))
    return render_template("target.html", target=t, scan=scan_data,
                           scan_count=scan_count)


@app.route("/api/target/<int:target_id>/trends")
def trends(target_id):
    """Time-series counts across every scan, for the trend chart."""
    rows = db.get_scans_for_target(target_id)
    return jsonify({
        "labels": [r["scanned_at"] for r in rows],
        "subdomains": [r["subdomains"] for r in rows],
        "open_ports": [r["open_ports"] for r in rows],
        "emails": [r["emails"] for r in rows],
    })


@app.template_filter("yesno")
def yesno(value):
    return "yes" if value else "no"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
