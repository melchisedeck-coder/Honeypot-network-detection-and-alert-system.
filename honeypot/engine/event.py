from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AttackEvent:
    attacker_ip:    str
    attack_type:    str
    target_service: str
    severity:       str
    port:           int
    timestamp:      datetime = field(default_factory=datetime.utcnow)
    payload:        Optional[str] = None
    target_page:    Optional[str] = None
    user_agent:     Optional[str] = None
    session_uuid:   Optional[str] = None
    protocol:       str = "TCP"
    country:        Optional[str] = None
    city:           Optional[str] = None
    latitude:       Optional[str] = None
    longitude:      Optional[str] = None
