from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from dashboard.database import Base


class Report(Base):
    __tablename__ = "reports"

    report_id    = Column(Integer, primary_key=True, autoincrement=True)
    admin_id     = Column(Integer, ForeignKey("admin_users.admin_id"), nullable=True)
    title        = Column(String(255), nullable=False)
    report_type  = Column(String(50), default="Daily")
    date_from    = Column(DateTime, nullable=True)
    date_to      = Column(DateTime, nullable=True)
    file_path    = Column(String(512), nullable=True)
    summary      = Column(Text, nullable=True)
    generated_at = Column(DateTime, server_default=func.now())

    def to_dict(self):
        return {
            "report_id":    self.report_id,
            "title":        self.title,
            "report_type":  self.report_type,
            "date_from":    self.date_from.isoformat() if self.date_from else None,
            "date_to":      self.date_to.isoformat() if self.date_to else None,
            "file_path":    self.file_path,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
        }
