from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from dashboard.database import Base


class AttackerSession(Base):
    __tablename__ = "attacker_sessions"

    session_id      = Column(Integer, primary_key=True, autoincrement=True)
    session_uuid    = Column(String(100), unique=True, nullable=False)
    attacker_ip     = Column(String(45), nullable=False, index=True)
    service         = Column(String(50), nullable=False)
    started_at      = Column(DateTime, server_default=func.now())
    ended_at        = Column(DateTime, nullable=True)
    credentials_tried = Column(Text, nullable=True)
    commands_run    = Column(Text, nullable=True)
    total_events    = Column(Integer, default=0)

    def to_dict(self):
        return {
            "session_id":   self.session_id,
            "session_uuid": self.session_uuid,
            "attacker_ip":  self.attacker_ip,
            "service":      self.service,
            "started_at":   self.started_at.isoformat() if self.started_at else None,
            "ended_at":     self.ended_at.isoformat() if self.ended_at else None,
            "total_events": self.total_events,
        }
