"""
Main launcher — starts the honeypot services and the admin dashboard together.

Usage:
    python run.py              # starts everything
    python run.py --dashboard  # dashboard only (no honeypot services)
    python run.py --honeypot   # honeypot services only (no dashboard)
"""
import sys
import os
import threading

# Make sure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from loguru import logger


def start_honeypot_services():
    from honeypot.engine import event_queue, start_logging_engine
    from honeypot.services.ftp_emulator import start_ftp_honeypot
    from honeypot.services.db_emulator  import start_db_honeypot
    from honeypot.web.app import honeypot_app, WEB_PORT

    # SSH emulator uses raw sockets — AV exclusion required for this import
    try:
        from honeypot.services.ssh_emulator import start_ssh_honeypot
    except (ImportError, OSError) as _e:
        logger.warning(f"[SSH] Module unavailable ({_e}). Add project folder to AV exclusions.")
        start_ssh_honeypot = None

    # Start central logging engine (consumes event queue)
    start_logging_engine()

    # Start SSH honeypot in background thread
    if start_ssh_honeypot:
        threading.Thread(target=start_ssh_honeypot, args=(event_queue,), daemon=True).start()
    else:
        logger.warning("[SSH] Skipped — add project folder to Windows Defender exclusions to enable")

    # Start FTP honeypot in background thread
    threading.Thread(target=start_ftp_honeypot, args=(event_queue,), daemon=True).start()

    # Start DB port honeypot in background thread
    threading.Thread(target=start_db_honeypot, args=(event_queue,), daemon=True).start()

    # Start fake website in background thread
    logger.info(f"[WEB] Honeypot website starting on port {WEB_PORT}")
    threading.Thread(
        target=lambda: honeypot_app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False),
        daemon=True
    ).start()


def start_dashboard():
    from dashboard.main import create_app, socketio
    import os

    app  = create_app()
    port = int(os.getenv("DASHBOARD_PORT", 5000))
    logger.info(f"[DASHBOARD] Admin dashboard starting on http://localhost:{port}")
    logger.info(f"[DASHBOARD] Login: admin / Admin@2026!")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--dashboard" in args:
        # Dashboard only
        start_dashboard()

    elif "--honeypot" in args:
        # Honeypot services only (no dashboard)
        start_honeypot_services()
        logger.info("[RUN] Honeypot services running. Press Ctrl+C to stop.")
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("[RUN] Stopping.")

    else:
        # Full system: honeypot + dashboard
        logger.info("=" * 60)
        logger.info("  KIU Honeypot System - Starting All Services")
        logger.info("=" * 60)
        start_honeypot_services()
        start_dashboard()  # This blocks — runs the dashboard in the main thread
