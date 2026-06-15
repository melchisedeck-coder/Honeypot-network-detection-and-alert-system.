from sqlalchemy import Column, Integer, String, Text, Enum, DateTime
from sqlalchemy.sql import func
from dashboard.database import Base


class SecurityRecommendation(Base):
    __tablename__ = "security_recommendations"

    rec_id       = Column(Integer, primary_key=True, autoincrement=True)
    attack_type  = Column(String(100), nullable=False)
    title        = Column(String(255), nullable=False)
    description  = Column(Text, nullable=False)
    priority     = Column(Enum("Low", "Medium", "High", "Critical", name="rec_priority_enum"), default="Medium")
    created_at   = Column(DateTime, server_default=func.now())

    def to_dict(self):
        return {
            "rec_id":      self.rec_id,
            "attack_type": self.attack_type,
            "title":       self.title,
            "description": self.description,
            "priority":    self.priority,
        }
