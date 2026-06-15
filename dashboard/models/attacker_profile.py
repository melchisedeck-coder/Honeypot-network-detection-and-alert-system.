from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.sql import func
from dashboard.database import Base


class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    profile_id            = Column(Integer, primary_key=True, autoincrement=True)
    attacker_ip           = Column(String(45), unique=True, nullable=False, index=True)
    country               = Column(String(100), nullable=True)
    city                  = Column(String(100), nullable=True)
    isp                   = Column(String(255), nullable=True)
    total_attempts        = Column(Integer, default=0)
    first_seen            = Column(DateTime, server_default=func.now())
    last_seen             = Column(DateTime, server_default=func.now(), onupdate=func.now())
    risk_score            = Column(Float, default=0.0)
    is_blacklisted        = Column(Boolean, default=False)
    blacklisted_at        = Column(DateTime, nullable=True)
    notes                 = Column(Text, nullable=True)
    high_severity_count   = Column(Integer, default=0)
    critical_severity_count = Column(Integer, default=0)

    def compute_risk_score(self):
        volume  = min(self.total_attempts / 100, 1.0) * 3.0
        hs      = (self.high_severity_count + self.critical_severity_count)
        sev_rate = hs / max(self.total_attempts, 1)
        severity = min(sev_rate, 1.0) * 7.0
        return round(volume + severity, 2)

    def to_dict(self):
        return {
            "profile_id":   self.profile_id,
            "attacker_ip":  self.attacker_ip,
            "country":      self.country,
            "city":         self.city,
            "isp":          self.isp,
            "total_attempts": self.total_attempts,
            "first_seen":   self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":    self.last_seen.isoformat() if self.last_seen else None,
            "risk_score":   self.risk_score,
            "is_blacklisted": self.is_blacklisted,
        }
