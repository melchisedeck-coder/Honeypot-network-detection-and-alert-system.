from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:MERCHISEDECK@localhost:5432/honeypot_db"
)

engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist."""
    import dashboard.models.admin_user          # noqa
    import dashboard.models.attack_log          # noqa
    import dashboard.models.attacker_profile    # noqa
    import dashboard.models.attacker_session    # noqa
    import dashboard.models.alert_history       # noqa
    import dashboard.models.alert_config        # noqa
    import dashboard.models.security_recommendation  # noqa
    import dashboard.models.report              # noqa
    Base.metadata.create_all(bind=engine)
    print("[DB] All tables created successfully.")
