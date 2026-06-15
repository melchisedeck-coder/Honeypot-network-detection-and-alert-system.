"""
Alert service: checks thresholds and dispatches email/SMS alerts in a background thread.
"""
import os
import smtplib
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger

from dashboard.database import SessionLocal
from dashboard.models.alert_history import AlertHistory
from dashboard.models.alert_config import AlertConfig

# In-memory counter: { attacker_ip: [timestamps] }
_event_counters: dict = {}
_lock = threading.Lock()


def record_event(attacker_ip: str, attack_type: str, severity: str) -> bool:
    """
    Returns True if an alert should be dispatched.
    Tracks events per IP within the configured time window.
    """
    db = SessionLocal()
    try:
        config = db.query(AlertConfig).filter_by(admin_id=1).first()
        threshold = config.email_threshold if config else int(os.getenv("EMAIL_ALERT_THRESHOLD", 3))
        window    = config.time_window_seconds if config else int(os.getenv("ALERT_TIME_WINDOW_SECONDS", 300))
    finally:
        db.close()

    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window)

    with _lock:
        timestamps = _event_counters.get(attacker_ip, [])
        timestamps = [t for t in timestamps if t > cutoff]
        timestamps.append(now)
        _event_counters[attacker_ip] = timestamps
        count = len(timestamps)

    if count == threshold:
        threading.Thread(
            target=_dispatch_alert,
            args=(attacker_ip, attack_type, severity, count),
            daemon=True,
        ).start()
        return True
    return False


def _dispatch_alert(attacker_ip: str, attack_type: str, severity: str, event_count: int):
    db = SessionLocal()
    try:
        config = db.query(AlertConfig).filter_by(admin_id=1).first()
        subject = f"[HONEYPOT ALERT] {severity} — {attack_type} from {attacker_ip}"
        body = (
            f"Security Alert — KIU Honeypot System\n\n"
            f"Attacker IP : {attacker_ip}\n"
            f"Attack Type : {attack_type}\n"
            f"Severity    : {severity}\n"
            f"Event Count : {event_count} events in the last window\n"
            f"Timestamp   : {datetime.utcnow().isoformat()} UTC\n\n"
            f"Login to the dashboard to review: http://localhost:5000\n"
        )

        channel_used = []
        notify_email = config.notify_email if config else os.getenv("ADMIN_EMAIL")
        notify_phone = config.notify_phone if config else os.getenv("ADMIN_PHONE_NUMBER")

        email_ok = (config.email_enabled if config else True) and notify_email
        sms_ok   = (config.sms_enabled   if config else True) and notify_phone

        if email_ok:
            sent = _send_email(notify_email, subject, body)
            if sent:
                channel_used.append("Email")

        if sms_ok:
            sent = _send_sms(notify_phone, f"[HONEYPOT] {severity} alert: {attack_type} from {attacker_ip}")
            if sent:
                channel_used.append("SMS")

        channel = "Both" if len(channel_used) == 2 else (channel_used[0] if channel_used else "Email")

        record = AlertHistory(
            attacker_ip=attacker_ip,
            attack_type=attack_type,
            severity=severity,
            channel=channel,
            message=body,
            triggered_at=datetime.utcnow(),
        )
        db.add(record)
        db.commit()
        logger.info(f"[ALERT] Dispatched {channel} alert for {attacker_ip}")
    except Exception as e:
        logger.error(f"[ALERT] Dispatch failed: {e}")
        db.rollback()
    finally:
        db.close()


def _send_email(to_addr: str, subject: str, body: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")

    if not smtp_user or not smtp_pass:
        logger.warning("[EMAIL] SMTP credentials not configured.")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = to_addr
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_addr, msg.as_string())
        logger.info(f"[EMAIL] Sent alert to {to_addr}")
        return True
    except Exception as e:
        logger.error(f"[EMAIL] Failed: {e}")
        return False


def _send_sms(to_number: str, message: str) -> bool:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token  = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_FROM_NUMBER")

    if not account_sid or account_sid == "your_account_sid_here":
        logger.warning("[SMS] Twilio not configured.")
        return False

    try:
        from twilio.rest import Client
        client = Client(account_sid, auth_token)
        client.messages.create(body=message, from_=from_number, to=to_number)
        logger.info(f"[SMS] Sent alert to {to_number}")
        return True
    except Exception as e:
        logger.error(f"[SMS] Failed: {e}")
        return False
