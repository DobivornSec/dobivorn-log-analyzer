"""GeoIP resolver utility with local cache."""

from typing import Optional

import requests


class GeoIPResolver:
    def __init__(self, enabled: bool = False, timeout: int = 3) -> None:
        self.enabled = enabled
        self.timeout = timeout
        self.cache: dict[str, Optional[dict]] = {}

    def get_location(self, ip: str) -> Optional[dict]:
        if not self.enabled:
            return None
        if ip in self.cache:
            return self.cache[ip]

        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                location = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                }
                self.cache[ip] = location
                return location
        except requests.RequestException:
            pass

        self.cache[ip] = None
        return None
