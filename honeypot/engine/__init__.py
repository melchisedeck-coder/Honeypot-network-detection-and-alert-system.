"""
Central logging engine — consumes AttackEvent objects from the queue,
persists them to the database, updates attacker profiles, and triggers alerts.
"""
import queue
import threading
from datetime import datetime
from loguru import logger

from honeypot.engine.event import AttackEvent
from honeypot.engine.geoip import geolocate

event_queue: queue.Queue = queue.Queue()


def _process_events():
    from dashboard.database import SessionLocal
    from dashboard.models.attack_log import AttackLog
    from dashboard.models.attacker_profile import AttackerProfile
    from dashboard.services.alert_service import record_event

    while True:
        try:
            event: AttackEvent = event_queue.get(timeout=1)
        except queue.Empty:
            continue

        db = SessionLocal()
        try:
            geo = geolocate(event.attacker_ip)
            event.country   = geo["country"]
            event.city      = geo["city"]
            event.latitude  = geo["latitude"]
            event.longitude = geo["longitude"]

            log = AttackLog(
                attacker_ip=event.attacker_ip,
                country=event.country,
                city=event.city,
                latitude=event.latitude,
                longitude=event.longitude,
                attack_type=event.attack_type,
                target_service=event.target_service,
                target_page=event.target_page,
                payload=event.payload,
                severity=event.severity,
                protocol=event.protocol,
                port=event.port,
                user_agent=event.user_agent,
                session_id=event.session_uuid,
                timestamp=event.timestamp,
            )
            db.add(log)

            profile = db.query(AttackerProfile).filter_by(attacker_ip=event.attacker_ip).first()
            if not profile:
                profile = AttackerProfile(
                    attacker_ip=event.attacker_ip,
                    country=event.country,
                    city=event.city,
                    isp=geo.get("isp"),
                )
                db.add(profile)

            profile.total_attempts = (profile.total_attempts or 0) + 1
            profile.last_seen = datetime.utcnow()
            if event.severity == "High":
                profile.high_severity_count = (profile.high_severity_count or 0) + 1
            elif event.severity == "Critical":
                profile.critical_severity_count = (profile.critical_severity_count or 0) + 1
            profile.risk_score = profile.compute_risk_score()

            db.commit()

            # Push live event to WebSocket
            try:
                from dashboard.main import socketio
                socketio.emit("new_attack", log.to_dict(), namespace="/live")
            except Exception:
                pass

            record_event(event.attacker_ip, event.attack_type, event.severity)
            logger.info(f"[ENGINE] {event.attack_type} from {event.attacker_ip} [{event.severity}]")

        except Exception as e:
            logger.error(f"[ENGINE] Error: {e}")
            db.rollback()
        finally:
            db.close()
            event_queue.task_done()


def start_logging_engine():
    t = threading.Thread(target=_process_events, daemon=True)
    t.start()
    logger.info("[ENGINE] Logging engine started.")
