"""
Fake university website honeypot.
Every request is logged as an attack event.
"""
import os
import uuid
from flask import Flask, request, render_template, redirect, url_for

from honeypot.engine.event import AttackEvent
from honeypot.engine.detector import classify_attack

WEB_PORT = int(os.getenv("HONEYPOT_WEB_PORT", 5001))

honeypot_app = Flask(__name__, template_folder="templates")


@honeypot_app.before_request
def capture_request():
    """Capture and analyse every incoming HTTP request."""
    from honeypot.engine import event_queue

    ip      = request.remote_addr or "0.0.0.0"
    path    = request.path
    method  = request.method
    payload = ""

    if method == "POST":
        form_data = request.form.to_dict()
        payload   = str(form_data)

    # Include query string in analysis
    full_payload = payload + " " + request.query_string.decode("utf-8", errors="replace")

    attack_type, severity = classify_attack(payload=full_payload, path=path, service="Web")

    event = AttackEvent(
        attacker_ip=ip,
        attack_type=attack_type,
        target_service="Web",
        severity=severity,
        port=WEB_PORT,
        payload=full_payload[:1000] if full_payload.strip() else None,
        target_page=path,
        user_agent=request.headers.get("User-Agent", "")[:512],
        session_uuid=str(uuid.uuid4()),
        protocol="HTTP",
    )
    event_queue.put(event)


@honeypot_app.route("/")
def index():
    return render_template("index.html")


@honeypot_app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@honeypot_app.route("/admin", methods=["GET", "POST"])
def admin():
    return render_template("admin.html")


@honeypot_app.route("/portal", methods=["GET", "POST"])
def portal():
    return render_template("portal.html")


@honeypot_app.route("/<path:path>")
def catch_all(path):
    """Catch all other paths — port scan recon."""
    return "404 Not Found", 404
