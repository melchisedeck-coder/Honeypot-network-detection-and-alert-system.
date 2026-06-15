import os
import socket
import threading
from loguru import logger
from honeypot.engine.event import AttackEvent

SSH_PORT   = int(os.getenv("HONEYPOT_SSH_PORT", 2222))
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" + bytes([13, 10])


def _handle(conn, ip, q):
    try:
        conn.settimeout(15)
        conn.sendall(SSH_BANNER)
        try:
            raw = conn.recv(512)
        except OSError:
            raw = b""
        payload = raw.decode("utf-8", errors="replace").strip() or "SSH probe"
        logger.warning(f"[SSH] {ip} | {repr(payload[:80])}")
        q.put(AttackEvent(
            attacker_ip=ip, attack_type="SSH Brute Force",
            target_service="SSH", severity="High",
            port=SSH_PORT, payload=payload[:512], protocol="TCP",
        ))
    except Exception as e:
        logger.debug(f"[SSH] {ip}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def start_ssh_honeypot(event_queue):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", SSH_PORT))
    srv.listen(100)
    logger.info(f"[SSH] Honeypot listening on port {SSH_PORT}")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_handle,
                             args=(conn, addr[0], event_queue),
                             daemon=True).start()
        except Exception as e:
            logger.error(f"[SSH] Accept error: {e}")
