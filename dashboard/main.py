"""
Admin Dashboard — Flask app with Socket.IO live feed.
Serves the admin UI and all API routes.
"""
import os
import sys

# Make project root importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, redirect, url_for, request, jsonify, session, send_file
from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
from loguru import logger
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"]              = os.getenv("SECRET_KEY", "dev_secret")
app.config["JWT_SECRET_KEY"]          = os.getenv("JWT_SECRET_KEY", "dev_jwt")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

CORS(app)
jwt     = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent", namespace="/live")
limiter  = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# ── Import models and DB ──────────────────────────────────────────────────
from dashboard.database import init_db, SessionLocal
from dashboard.models.admin_user import AdminUser
from dashboard.models.attack_log import AttackLog
from dashboard.models.attacker_profile import AttackerProfile
from dashboard.models.alert_history import AlertHistory
from dashboard.models.alert_config import AlertConfig
from dashboard.models.security_recommendation import SecurityRecommendation
from dashboard.models.report import Report
from dashboard.services.auth_service import verify_login, create_default_admin

# ─────────────────────────────────────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "admin_id" not in session:
        return redirect(url_for("login_page"))
    return redirect(url_for("dashboard_overview"))


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = verify_login(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    session["admin_id"] = user.admin_id
    session["username"] = user.username
    session["role"]     = user.role

    token = create_access_token(identity=str(user.admin_id))
    return jsonify({
        "message": "Login successful",
        "token":   token,
        "admin":   {"id": user.admin_id, "username": user.username, "role": user.role},
    })


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD PAGES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard_overview():
    db = SessionLocal()
    try:
        total_attacks = db.query(AttackLog).count()
        today_start   = datetime.utcnow().replace(hour=0, minute=0, second=0)
        attacks_today = db.query(AttackLog).filter(AttackLog.timestamp >= today_start).count()
        active_ips    = db.query(AttackerProfile).count()
        unresolved    = db.query(AlertHistory).filter_by(is_resolved=False).count()
        latest_attacks = (db.query(AttackLog)
                          .order_by(AttackLog.timestamp.desc()).limit(10).all())
    finally:
        db.close()

    return render_template("dashboard/overview.html",
        total_attacks=total_attacks,
        attacks_today=attacks_today,
        active_ips=active_ips,
        unresolved_alerts=unresolved,
        latest_attacks=latest_attacks,
        username=session.get("username"),
    )


@app.route("/dashboard/attacks")
@login_required
def attacks_page():
    return render_template("dashboard/attacks.html", username=session.get("username"))


@app.route("/dashboard/attackers")
@login_required
def attackers_page():
    return render_template("dashboard/attackers.html", username=session.get("username"))


@app.route("/dashboard/alerts")
@login_required
def alerts_page():
    return render_template("dashboard/alerts.html", username=session.get("username"))


@app.route("/dashboard/reports")
@login_required
def reports_page():
    return render_template("dashboard/reports.html", username=session.get("username"))


@app.route("/dashboard/settings")
@login_required
def settings_page():
    db = SessionLocal()
    try:
        config = db.query(AlertConfig).filter_by(admin_id=session["admin_id"]).first()
        recs   = db.query(SecurityRecommendation).order_by(SecurityRecommendation.priority).all()
    finally:
        db.close()
    return render_template("dashboard/settings.html",
        config=config, recommendations=recs, username=session.get("username"))


# ─────────────────────────────────────────────────────────────────────────────
#  ATTACKS API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/attacks")
@login_required
def api_attacks():
    db   = SessionLocal()
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    severity = request.args.get("severity")
    attack_type = request.args.get("type")

    try:
        q = db.query(AttackLog)
        if severity:
            q = q.filter(AttackLog.severity == severity)
        if attack_type:
            q = q.filter(AttackLog.attack_type == attack_type)
        total = q.count()
        logs  = q.order_by(AttackLog.timestamp.desc()).offset((page-1)*limit).limit(limit).all()
        return jsonify({
            "total": total, "page": page, "limit": limit,
            "data":  [l.to_dict() for l in logs],
        })
    finally:
        db.close()


@app.route("/api/attacks/stats")
@login_required
def api_attack_stats():
    db = SessionLocal()
    try:
        from sqlalchemy import func
        type_counts = dict(
            db.query(AttackLog.attack_type, func.count(AttackLog.log_id))
              .group_by(AttackLog.attack_type).all()
        )
        severity_counts = dict(
            db.query(AttackLog.severity, func.count(AttackLog.log_id))
              .group_by(AttackLog.severity).all()
        )
        service_counts = dict(
            db.query(AttackLog.target_service, func.count(AttackLog.log_id))
              .group_by(AttackLog.target_service).all()
        )
        # Last 7 days breakdown
        week_data = []
        for i in range(6, -1, -1):
            day_start = (datetime.utcnow() - timedelta(days=i)).replace(hour=0, minute=0, second=0)
            day_end   = day_start + timedelta(days=1)
            count     = db.query(AttackLog).filter(
                AttackLog.timestamp >= day_start,
                AttackLog.timestamp < day_end
            ).count()
            week_data.append({"date": day_start.strftime("%Y-%m-%d"), "count": count})

        return jsonify({
            "by_type":     type_counts,
            "by_severity": severity_counts,
            "by_service":  service_counts,
            "last_7_days": week_data,
        })
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
#  ATTACKERS API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/attackers")
@login_required
def api_attackers():
    db    = SessionLocal()
    page  = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    try:
        total    = db.query(AttackerProfile).count()
        profiles = (db.query(AttackerProfile)
                    .order_by(AttackerProfile.risk_score.desc())
                    .offset((page-1)*limit).limit(limit).all())
        return jsonify({
            "total": total, "page": page,
            "data":  [p.to_dict() for p in profiles],
        })
    finally:
        db.close()


@app.route("/api/attackers/<ip>")
@login_required
def api_attacker_detail(ip):
    db = SessionLocal()
    try:
        profile = db.query(AttackerProfile).filter_by(attacker_ip=ip).first()
        if not profile:
            return jsonify({"error": "Not found"}), 404
        logs = (db.query(AttackLog).filter_by(attacker_ip=ip)
                .order_by(AttackLog.timestamp.desc()).limit(50).all())
        data = profile.to_dict()
        data["recent_attacks"] = [l.to_dict() for l in logs]
        return jsonify(data)
    finally:
        db.close()


@app.route("/api/attackers/<ip>/blacklist", methods=["POST"])
@login_required
def api_blacklist(ip):
    db = SessionLocal()
    try:
        profile = db.query(AttackerProfile).filter_by(attacker_ip=ip).first()
        if not profile:
            return jsonify({"error": "Not found"}), 404
        profile.is_blacklisted = True
        profile.blacklisted_at = datetime.utcnow()
        db.commit()
        return jsonify({"message": f"{ip} blacklisted"})
    finally:
        db.close()


@app.route("/api/attackers/map")
@login_required
def api_attackers_map():
    db = SessionLocal()
    try:
        profiles = db.query(AttackerProfile).filter(
            AttackerProfile.latitude.isnot(None)
        ).all()
        features = []
        for p in profiles:
            features.append({
                "ip":        p.attacker_ip,
                "country":   p.country,
                "city":      p.city,
                "lat":       float(p.latitude) if p.latitude else None,
                "lng":       float(p.longitude) if p.longitude else None,
                "risk":      p.risk_score,
                "attempts":  p.total_attempts,
            })
        return jsonify(features)
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
#  ALERTS API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/alerts")
@login_required
def api_alerts():
    db    = SessionLocal()
    page  = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    try:
        total  = db.query(AlertHistory).count()
        alerts = (db.query(AlertHistory)
                  .order_by(AlertHistory.triggered_at.desc())
                  .offset((page-1)*limit).limit(limit).all())
        return jsonify({"total": total, "data": [a.to_dict() for a in alerts]})
    finally:
        db.close()


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["PATCH"])
@login_required
def api_resolve_alert(alert_id):
    db = SessionLocal()
    try:
        alert = db.query(AlertHistory).get(alert_id)
        if not alert:
            return jsonify({"error": "Not found"}), 404
        alert.is_resolved = True
        alert.resolved_at = datetime.utcnow()
        db.commit()
        return jsonify({"message": "Alert resolved"})
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
#  SETTINGS API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/settings/alerts", methods=["GET", "PUT"])
@login_required
def api_alert_settings():
    db = SessionLocal()
    try:
        config = db.query(AlertConfig).filter_by(admin_id=session["admin_id"]).first()
        if request.method == "GET":
            if not config:
                return jsonify({"error": "No config found"}), 404
            return jsonify(config.to_dict())

        data = request.get_json()
        if not config:
            config = AlertConfig(admin_id=session["admin_id"])
            db.add(config)

        config.email_enabled       = data.get("email_enabled", True)
        config.sms_enabled         = data.get("sms_enabled", True)
        config.email_threshold     = data.get("email_threshold", 3)
        config.sms_threshold       = data.get("sms_threshold", 10)
        config.time_window_seconds = data.get("time_window_seconds", 300)
        config.notify_email        = data.get("notify_email")
        config.notify_phone        = data.get("notify_phone")
        db.commit()
        return jsonify({"message": "Settings saved"})
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
#  REPORTS API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/reports")
@login_required
def api_reports():
    db = SessionLocal()
    try:
        reports = db.query(Report).order_by(Report.generated_at.desc()).all()
        return jsonify([r.to_dict() for r in reports])
    finally:
        db.close()


@app.route("/api/reports/generate", methods=["POST"])
@login_required
def api_generate_report():
    from dashboard.services.report_service import generate_pdf_report
    db = SessionLocal()
    try:
        data      = request.get_json() or {}
        title     = data.get("title", f"Honeypot Report {datetime.utcnow().strftime('%Y-%m-%d')}")
        file_path = generate_pdf_report(title, session["admin_id"])

        record = Report(
            admin_id=session["admin_id"],
            title=title,
            file_path=file_path,
            generated_at=datetime.utcnow(),
        )
        db.add(record)
        db.commit()
        return jsonify({"message": "Report generated", "file_path": file_path})
    finally:
        db.close()


@app.route("/api/reports/<int:report_id>/download")
@login_required
def api_download_report(report_id):
    db = SessionLocal()
    try:
        report = db.query(Report).get(report_id)
        if not report or not os.path.exists(report.file_path):
            return jsonify({"error": "File not found"}), 404
        return send_file(report.file_path, as_attachment=True)
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
#  SOCKET.IO
# ─────────────────────────────────────────────────────────────────────────────

@socketio.on("connect", namespace="/live")
def on_connect():
    logger.debug("[WS] Client connected to live feed")
    emit("status", {"message": "Connected to live attack feed"})


@socketio.on("disconnect", namespace="/live")
def on_disconnect():
    logger.debug("[WS] Client disconnected from live feed")


# ─────────────────────────────────────────────────────────────────────────────
#  STARTUP
# ─────────────────────────────────────────────────────────────────────────────

def create_app():
    init_db()
    create_default_admin()
    _seed_recommendations()
    return app


def _seed_recommendations():
    """Insert default security recommendations if table is empty."""
    db = SessionLocal()
    try:
        if db.query(SecurityRecommendation).count() == 0:
            recs = [
                SecurityRecommendation(attack_type="SSH Brute Force", priority="High",
                    title="Disable Password Authentication for SSH",
                    description="Use SSH key-based authentication only. Set PasswordAuthentication no in /etc/ssh/sshd_config."),
                SecurityRecommendation(attack_type="SSH Brute Force", priority="High",
                    title="Implement Fail2ban for SSH",
                    description="Install fail2ban to automatically block IPs after repeated SSH failures."),
                SecurityRecommendation(attack_type="SQL Injection", priority="Critical",
                    title="Use Parameterized Queries",
                    description="Never concatenate user input directly into SQL strings. Use prepared statements or an ORM."),
                SecurityRecommendation(attack_type="SQL Injection", priority="High",
                    title="Enable Web Application Firewall",
                    description="Deploy a WAF such as ModSecurity to filter SQL injection patterns at the network layer."),
                SecurityRecommendation(attack_type="XSS", priority="High",
                    title="Implement Content Security Policy",
                    description="Add CSP headers to restrict which scripts can execute on your pages."),
                SecurityRecommendation(attack_type="XSS", priority="High",
                    title="Sanitize All Output",
                    description="Escape HTML entities in all user-supplied data rendered on the page."),
                SecurityRecommendation(attack_type="FTP Unauthorized", priority="Medium",
                    title="Disable Anonymous FTP",
                    description="Ensure FTP anonymous access is disabled. Consider replacing FTP with SFTP."),
                SecurityRecommendation(attack_type="Port Scan", priority="Low",
                    title="Use Port Knocking",
                    description="Implement port knocking to hide SSH and other service ports from scanners."),
                SecurityRecommendation(attack_type="Directory Traversal", priority="High",
                    title="Validate File Path Inputs",
                    description="Reject any path containing ../ sequences. Use os.path.realpath() and verify files stay within allowed directory."),
                SecurityRecommendation(attack_type="DB Probe", priority="High",
                    title="Restrict Database Port Access",
                    description="Database ports should never be accessible from the internet. Use firewall rules to allow only application server IP."),
            ]
            db.add_all(recs)
            db.commit()
            logger.info("[SEED] Security recommendations inserted.")
    except Exception as e:
        logger.warning(f"[SEED] Could not seed recommendations: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    create_app()
    port = int(os.getenv("DASHBOARD_PORT", 5000))
    logger.info(f"[DASHBOARD] Starting on port {port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
