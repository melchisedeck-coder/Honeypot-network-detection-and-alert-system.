from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from dashboard.database import Base


class AlertConfig(Base):
    __tablename__ = "alert_config"

    config_id              = Column(Integer, primary_key=True, autoincrement=True)
    admin_id               = Column(Integer, nullable=False, default=1)
    email_enabled          = Column(Boolean, default=True)
    sms_enabled            = Column(Boolean, default=True)
    email_threshold        = Column(Integer, default=3)
    sms_threshold          = Column(Integer, default=10)
    time_window_seconds    = Column(Integer, default=300)
    notify_email           = Column(String(100), nullable=True)
    notify_phone           = Column(String(20), nullable=True)
    alert_on_port_scan     = Column(Boolean, default=True)
    alert_on_brute_force   = Column(Boolean, default=True)
    alert_on_sqli          = Column(Boolean, default=True)
    alert_on_xss           = Column(Boolean, default=True)
    updated_at             = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def to_dict(self):
        return {
            "config_id":           self.config_id,
            "email_enabled":       self.email_enabled,
            "sms_enabled":         self.sms_enabled,
            "email_threshold":     self.email_threshold,
            "sms_threshold":       self.sms_threshold,
            "time_window_seconds": self.time_window_seconds,
            "notify_email":        self.notify_email,
            "notify_phone":        self.notify_phone,
        }
