"""
GeoIP resolution, RFC1918 classification, and Haversine distance calculator.
"""

import ipaddress
import math
from typing import Dict, Optional, Tuple
from ..core.models import GeoLocation


class GeoIPResolver:
    """Resolves IP addresses to geographical location with built-in cache and fallbacks."""

    # Curated simulation / offline mapping for common test & public ranges
    MOCK_GEO_DB: Dict[str, Tuple[str, str, str, float, float, str]] = {
        # Format: prefix -> (Country, CountryCode, City, Lat, Long, ISP)
        "203.0.113": ("Russian Federation", "RU", "Moscow", 55.7558, 37.6173, "Rostelecom AS12389"),
        "198.51.100": ("China", "CN", "Beijing", 39.9042, 116.4074, "China Telecom AS4134"),
        "192.0.2": ("North Korea", "KP", "Pyongyang", 39.0392, 125.7625, "Star JV AS131279"),
        "185.220.101": ("Germany", "DE", "Frankfurt", 50.1109, 8.6821, "Tor Exit Node Network"),
        "45.33.32": ("United States", "US", "Fremont", 37.5485, -121.9886, "Linode LLC AS63949"),
        "104.244.42": ("United States", "US", "San Francisco", 37.7749, -122.4194, "Twitter Inc AS13414"),
        "8.8.8": ("United States", "US", "Mountain View", 37.3861, -122.0839, "Google LLC AS15169"),
        "1.1.1": ("Australia", "AU", "Sydney", -33.8688, 151.2093, "Cloudflare Inc AS13335"),
    }

    def __init__(self, offline_only: bool = True):
        self.offline_only = offline_only
        self._cache: Dict[str, GeoLocation] = {}

    def is_private_or_reserved(self, ip_str: str) -> bool:
        """Check if an IP address belongs to RFC 1918 or reserved ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_link_local
            )
        except ValueError:
            return False

    def resolve(self, ip_str: str) -> GeoLocation:
        """Resolve IP address to a GeoLocation object."""
        if ip_str in self._cache:
            return self._cache[ip_str]

        # Check offline prefix lookup first (allows simulated public locations for RFC5737 demo IPs)
        for prefix, details in self.MOCK_GEO_DB.items():
            if ip_str.startswith(prefix):
                country, code, city, lat, lon, isp = details
                geo = GeoLocation(
                    ip=ip_str,
                    country=country,
                    country_code=code,
                    city=city,
                    latitude=lat,
                    longitude=lon,
                    isp=isp,
                    is_private=False,
                )
                self._cache[ip_str] = geo
                return geo

        # Check private RFC1918 / loopback
        if self.is_private_or_reserved(ip_str):
            geo = GeoLocation(
                ip=ip_str,
                country="Internal Network",
                country_code="LOCAL",
                city="Local Subnet",
                latitude=0.0,
                longitude=0.0,
                isp="RFC1918 Private Network",
                is_private=True,
            )
            self._cache[ip_str] = geo
            return geo

        # Default fallback for unmapped external IPs
        # Deterministically assign plausible locations based on IP hash for realistic demo/presentation
        octets = ip_str.split(".")
        if len(octets) == 4 and all(o.isdigit() for o in octets):
            seed = int(octets[0]) + int(octets[1]) * 2
            simulated_locations = [
                ("United States", "US", "Ashburn", 39.0437, -77.4875, "Amazon AWS AS16509"),
                ("Netherlands", "NL", "Amsterdam", 52.3676, 4.9041, "DigitalOcean AS14061"),
                ("Brazil", "BR", "Sao Paulo", -23.5505, -46.6333, "Claro Brasil AS28573"),
                ("Singapore", "SG", "Singapore", 1.3521, 103.8198, "Singtel AS7473"),
                ("Japan", "JP", "Tokyo", 35.6762, 139.6503, "NTT Communications AS2914"),
            ]
            loc = simulated_locations[seed % len(simulated_locations)]
            geo = GeoLocation(
                ip=ip_str,
                country=loc[0],
                country_code=loc[1],
                city=loc[2],
                latitude=loc[3],
                longitude=loc[4],
                isp=loc[5],
                is_private=False,
            )
        else:
            geo = GeoLocation(ip=ip_str, country="Unknown", country_code="XX", is_private=False)

        self._cache[ip_str] = geo
        return geo

    @staticmethod
    def calculate_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate great-circle distance between two points on Earth using Haversine formula.
        """
        if (lat1 == 0.0 and lon1 == 0.0) or (lat2 == 0.0 and lon2 == 0.0):
            return 0.0

        r = 6371.0  # Earth's radius in kilometers
        d_lat = math.radians(lat2 - lat1)
        d_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(d_lat / 2) ** 2
            + math.cos(math.radians(lat1))
            * math.cos(math.radians(lat2))
            * math.sin(d_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return r * c
