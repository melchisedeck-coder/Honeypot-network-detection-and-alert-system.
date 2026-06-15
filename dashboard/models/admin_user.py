from sqlalchemy import Column, Integer, String, Enum, DateTime, Boolean
from sqlalchemy.sql import func
from dashboard.database import Base


class AdminUser(Base):
    __tablename__ = "admin_users"

    admin_id     = Column(Integer, primary_key=True, autoincrement=True)
    username     = Column(String(50), unique=True, nullable=False)
    email        = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role         = Column(Enum("superadmin", "admin", name="admin_role"), default="admin")
    is_active    = Column(Boolean, default=True)
    last_login   = Column(DateTime)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    created_at   = Column(DateTime, server_default=func.now())
    updated_at   = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<AdminUser {self.username} ({self.role})>"
