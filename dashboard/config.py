from dotenv import load_dotenv
import os

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_jwt_secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    # Alert thresholds
    EMAIL_ALERT_THRESHOLD = int(os.getenv("EMAIL_ALERT_THRESHOLD", 3))
    SMS_ALERT_THRESHOLD = int(os.getenv("SMS_ALERT_THRESHOLD", 10))
    ALERT_TIME_WINDOW = int(os.getenv("ALERT_TIME_WINDOW_SECONDS", 300))

    # Twilio
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
    TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER")
    ADMIN_PHONE_NUMBER = os.getenv("ADMIN_PHONE_NUMBER")

    # Email
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

    # GeoIP
    GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
