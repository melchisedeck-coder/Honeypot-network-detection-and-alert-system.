"""
FTP Honeypot — listens on HONEYPOT_FTP_PORT (default 2121).
Accepts connections, logs all credentials, always returns 530 Login Incorrect.
"""
import os
import threading
from loguru import logger
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

from honeypot.engine.event import AttackEvent

FTP_PORT = int(os.getenv("HONEYPOT_FTP_PORT", 2121))


class HoneypotFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._event_queue = None

    def on_connect(self):
        logger.warning(f"[FTP] Connection from {self.remote_ip}:{self.remote_port}")

    def on_login_failed(self, username, password):
        logger.warning(f"[FTP] {self.remote_ip} tried {username}:{password}")
        if self._event_queue:
            event = AttackEvent(
                attacker_ip=self.remote_ip,
                attack_type="FTP Unauthorized",
                target_service="FTP",
                severity="Medium",
                port=FTP_PORT,
                payload=f"{username}:{password}",
                protocol="TCP",
            )
            self._event_queue.put(event)

    def on_disconnect(self):
        pass


_event_queue_ref = None


class QueueFTPHandler(HoneypotFTPHandler):
    def on_login_failed(self, username, password):
        logger.warning(f"[FTP] {self.remote_ip} tried {username}:{password}")
        if _event_queue_ref:
            event = AttackEvent(
                attacker_ip=self.remote_ip,
                attack_type="FTP Unauthorized",
                target_service="FTP",
                severity="Medium",
                port=FTP_PORT,
                payload=f"{username}:{password}",
                protocol="TCP",
            )
            _event_queue_ref.put(event)


def start_ftp_honeypot(event_queue):
    global _event_queue_ref
    _event_queue_ref = event_queue

    authorizer = DummyAuthorizer()
    # No real users — every login attempt will fail

    handler = QueueFTPHandler
    handler.authorizer = authorizer
    handler.banner = "FTP server ready."
    handler.passive_ports = range(60000, 60100)

    server = FTPServer(("0.0.0.0", FTP_PORT), handler)
    logger.info(f"[FTP] Honeypot listening on port {FTP_PORT}")

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
