from passlib.hash import bcrypt
from datetime import datetime
from loguru import logger

from dashboard.database import SessionLocal
from dashboard.models.admin_user import AdminUser


def verify_login(username: str, password: str):
    """Returns AdminUser if credentials valid, None otherwise."""
    db = SessionLocal()
    try:
        user = db.query(AdminUser).filter_by(username=username, is_active=True).first()
        if not user:
            return None
        if user.locked_until and user.locked_until > datetime.utcnow():
            return None
        if bcrypt.verify(password, user.password_hash):
            user.failed_attempts = 0
            user.last_login = datetime.utcnow()
            db.commit()
            db.refresh(user)
            return user
        else:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                from datetime import timedelta
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                logger.warning(f"[AUTH] Account {username} locked after 5 failed attempts")
            db.commit()
            return None
    finally:
        db.close()


def hash_password(plain: str) -> str:
    return bcrypt.hash(plain)


def create_default_admin():
    """Creates the default superadmin if no users exist."""
    db = SessionLocal()
    try:
        exists = db.query(AdminUser).first()
        if not exists:
            admin = AdminUser(
                username="admin",
                email="admin@honeypot.local",
                password_hash=hash_password("Admin@2026!"),
                role="superadmin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            logger.info("[AUTH] Default admin created: admin / Admin@2026!")
    except Exception as e:
        logger.error(f"[AUTH] Failed to create default admin: {e}")
        db.rollback()
    finally:
        db.close()
