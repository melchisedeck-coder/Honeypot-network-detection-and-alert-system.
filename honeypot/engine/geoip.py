import os
import requests
from loguru import logger

_reader = None


def _load_maxmind():
    """Try to load the MaxMind GeoLite2 database if available."""
    global _reader
    db_path = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
    if os.path.exists(db_path):
        try:
            import geoip2.database
            _reader = geoip2.database.Reader(db_path)
            logger.info(f"[GeoIP] MaxMind database loaded from {db_path}")
        except Exception as e:
            logger.warning(f"[GeoIP] Could not load MaxMind DB: {e}")


_load_maxmind()


def geolocate(ip: str) -> dict:
    """
    Returns {'country': ..., 'city': ..., 'latitude': ..., 'longitude': ..., 'isp': ...}
    Falls back to ip-api.com free API if MaxMind DB is not available.
    """
    # Skip private/loopback IPs
    if ip.startswith(("127.", "10.", "192.168.", "172.")) or ip == "::1":
        return {"country": "Local Network", "city": "Local", "latitude": None, "longitude": None, "isp": "Local"}

    # Try MaxMind offline database first
    if _reader:
        try:
            response = _reader.city(ip)
            return {
                "country":   response.country.name or "Unknown",
                "city":      response.city.name or "Unknown",
                "latitude":  str(response.location.latitude) if response.location.latitude else None,
                "longitude": str(response.location.longitude) if response.location.longitude else None,
                "isp":       None,
            }
        except Exception:
            pass

    # Fall back to free ip-api.com (no key needed, 45 requests/minute limit)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,isp", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country":   data.get("country", "Unknown"),
                    "city":      data.get("city", "Unknown"),
                    "latitude":  str(data.get("lat")) if data.get("lat") else None,
                    "longitude": str(data.get("lon")) if data.get("lon") else None,
                    "isp":       data.get("isp"),
                }
    except Exception as e:
        logger.debug(f"[GeoIP] ip-api.com lookup failed for {ip}: {e}")

    return {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None, "isp": None}
