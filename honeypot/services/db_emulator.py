import os
import socket
import threading
from loguru import logger
from honeypot.engine.event import AttackEvent

DB_PORT = int(os.getenv("HONEYPOT_DB_PORT", 3307))

# MySQL 8.0 initial-handshake built from hex so the source has no null bytes
_H  = "53000000"                                    # packet header (83 bytes payload, seq=0)
_H += "0a"                                          # protocol version 10
_H += "382e302e33322d686f6e6579706f7400"            # "8.0.32-honeypot" + null
_H += "01000000"                                    # connection id = 1
_H += "1a2b3c4d5e6f7a8b"                           # auth data part-1 (8 bytes)
_H += "00"                                          # filler
_H += "fff7"                                        # capability flags low
_H += "21"                                          # charset = utf8
_H += "0200"                                        # status = autocommit
_H += "ff81"                                        # capability flags high
_H += "15"                                          # auth plugin data length = 21
_H += "00" * 10                                     # reserved
_H += "1a2b3c4d5e6f7a8b9c1b2c3d4e"               # auth data part-2 (13 bytes)
_H += "6d7973716c5f6e61746976655f70617373776f726400"  # "mysql_native_password" + null
MYSQL_GREETING = bytes.fromhex(_H)


def _handle(conn, ip, q):
    try:
        conn.settimeout(10)
        conn.sendall(MYSQL_GREETING)
        try:
            raw = conn.recv(512)
        except OSError:
            raw = b""
        payload = raw.decode("utf-8", errors="replace").strip() or "DB probe"
        logger.warning(f"[DB] {ip} | MySQL probe | {repr(payload[:80])}")
        q.put(AttackEvent(
            attacker_ip=ip, attack_type="DB Probe",
            target_service="Database", severity="High",
            port=DB_PORT, payload=payload[:512], protocol="TCP",
        ))
    except Exception as e:
        logger.debug(f"[DB] {ip}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def start_db_honeypot(event_queue):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", DB_PORT))
    srv.listen(50)
    logger.info(f"[DB] Honeypot listening on port {DB_PORT}")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_handle,
                             args=(conn, addr[0], event_queue),
                             daemon=True).start()
        except Exception as e:
            logger.error(f"[DB] Accept error: {e}")
