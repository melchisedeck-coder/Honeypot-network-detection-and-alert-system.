from sqlalchemy import Column, BigInteger, String, Enum, DateTime, Text, Integer
from sqlalchemy.sql import func
from dashboard.database import Base


class AttackLog(Base):
    __tablename__ = "attack_logs"

    log_id         = Column(BigInteger, primary_key=True, autoincrement=True)
    attacker_ip    = Column(String(45), nullable=False, index=True)
    attacker_mac   = Column(String(17), nullable=True)
    country        = Column(String(100), nullable=True)
    city           = Column(String(100), nullable=True)
    latitude       = Column(String(20), nullable=True)
    longitude      = Column(String(20), nullable=True)
    attack_type    = Column(
        Enum("Port Scan", "SSH Brute Force", "FTP Unauthorized",
             "SQL Injection", "XSS", "Directory Traversal",
             "DB Probe", "Other", name="attack_type_enum"),
        nullable=False
    )
    target_service = Column(
        Enum("Web", "SSH", "FTP", "Database", "Other", name="service_enum"),
        default="Web"
    )
    target_page    = Column(String(255), nullable=True)
    payload        = Column(Text, nullable=True)
    severity       = Column(
        Enum("Low", "Medium", "High", "Critical", name="severity_enum"),
        default="Low"
    )
    protocol       = Column(String(10), default="TCP")
    port           = Column(Integer, nullable=True)
    user_agent     = Column(String(512), nullable=True)
    session_id     = Column(String(100), nullable=True)
    timestamp      = Column(DateTime, server_default=func.now(), index=True)

    def to_dict(self):
        return {
            "log_id":         self.log_id,
            "attacker_ip":    self.attacker_ip,
            "country":        self.country,
            "city":           self.city,
            "latitude":       self.latitude,
            "longitude":      self.longitude,
            "attack_type":    self.attack_type,
            "target_service": self.target_service,
            "target_page":    self.target_page,
            "payload":        self.payload,
            "severity":       self.severity,
            "protocol":       self.protocol,
            "port":           self.port,
            "user_agent":     self.user_agent,
            "timestamp":      self.timestamp.isoformat() if self.timestamp else None,
        }
