from sqlalchemy import Column, Integer, String, Enum, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func
from dashboard.database import Base


class AlertHistory(Base):
    __tablename__ = "alert_history"

    alert_id      = Column(Integer, primary_key=True, autoincrement=True)
    admin_id      = Column(Integer, ForeignKey("admin_users.admin_id"), nullable=True)
    attacker_ip   = Column(String(45), nullable=False)
    attack_type   = Column(String(100), nullable=False)
    severity      = Column(Enum("Low", "Medium", "High", "Critical", name="alert_severity_enum"), default="Medium")
    channel       = Column(Enum("Email", "SMS", "Both", name="alert_channel_enum"), default="Email")
    message       = Column(Text, nullable=True)
    is_resolved   = Column(Boolean, default=False)
    resolved_at   = Column(DateTime, nullable=True)
    triggered_at  = Column(DateTime, server_default=func.now(), index=True)

    def to_dict(self):
        return {
            "alert_id":     self.alert_id,
            "attacker_ip":  self.attacker_ip,
            "attack_type":  self.attack_type,
            "severity":     self.severity,
            "channel":      self.channel,
            "message":      self.message,
            "is_resolved":  self.is_resolved,
            "resolved_at":  self.resolved_at.isoformat() if self.resolved_at else None,
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
        }
