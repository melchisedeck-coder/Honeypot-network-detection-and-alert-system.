# Celery is not used in this version.
# Alert dispatch is handled asynchronously via Python threading in:
#   dashboard/services/alert_service.py
#
# To add Celery later:
#   pip install celery redis
#   from celery import Celery
#   app = Celery('honeypot', broker='redis://localhost:6379/0')
