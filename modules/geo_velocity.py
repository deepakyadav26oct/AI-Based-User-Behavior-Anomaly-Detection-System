import math
from datetime import datetime
from typing import Dict, Any, Tuple, Optional

# Representative IP-to-Geo registry for internal corporate and simulated external nodes
KNOWN_GEO_MAPPINGS = {
    # Internal / Local Gateways
    '127.0.0.1': {'city': 'Delhi', 'country': 'India', 'lat': 28.6139, 'lon': 77.2090},
    '10.0.12.14': {'city': 'Delhi', 'country': 'India', 'lat': 28.6139, 'lon': 77.2090},
    '10.0.12.25': {'city': 'Delhi', 'country': 'India', 'lat': 28.6139, 'lon': 77.2090},
    '10.0.12.88': {'city': 'Mumbai', 'country': 'India', 'lat': 19.0760, 'lon': 72.8777},
    '192.168.1.45': {'city': 'Delhi', 'country': 'India', 'lat': 28.6139, 'lon': 77.2090},
    '192.168.2.15': {'city': 'Bengaluru', 'country': 'India', 'lat': 12.9716, 'lon': 77.5946},
    
    # External International Ingress Points
    '185.220.101.5': {'city': 'Frankfurt', 'country': 'Germany', 'lat': 50.1109, 'lon': 8.6821},
    '194.26.29.112': {'city': 'Moscow', 'country': 'Russia', 'lat': 55.7558, 'lon': 37.6173},
    '45.154.255.89': {'city': 'London', 'country': 'United Kingdom', 'lat': 51.5074, 'lon': -0.1278},
    '91.240.118.23': {'city': 'New York', 'country': 'United States', 'lat': 40.7128, 'lon': -74.0060},
    '103.152.220.10': {'city': 'Tokyo', 'country': 'Japan', 'lat': 35.6762, 'lon': 139.6503},
    '198.51.100.44': {'city': 'Sydney', 'country': 'Australia', 'lat': -33.8688, 'lon': 151.2093},
    '203.0.113.77': {'city': 'Singapore', 'country': 'Singapore', 'lat': 1.3521, 'lon': 103.8198},
}

DEFAULT_GEO = {'city': 'Corporate HQ', 'country': 'Domestic', 'lat': 28.6139, 'lon': 77.2090}

class GeoVelocityEngine:
    """
    Computes great-circle Haversine distances and velocity between successive user logins
    to identify Impossible Travel and VPN/credential spray attacks.
    """

    MAX_COMMERCIAL_FLIGHT_SPEED_KMH = 800.0  # standard Boeing/Airbus cruising limit

    @staticmethod
    def resolve_ip_location(ip: str) -> Dict[str, Any]:
        """Resolve IP address to city, country, latitude, and longitude."""
        cleaned_ip = ip.split(',')[0].strip() if ip else '127.0.0.1'
        return KNOWN_GEO_MAPPINGS.get(cleaned_ip, DEFAULT_GEO)

    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate the great-circle distance between two points on Earth in kilometers.
        Formula: 2 * R * asin(sqrt(sin^2(dlat/2) + cos(lat1) * cos(lat2) * sin^2(dlon/2)))
        """
        R = 6371.0  # Earth radius in kilometers

        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2.0) ** 2 + \
            math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return R * c

    @classmethod
    def evaluate_impossible_travel(
        cls,
        last_lat: Optional[float],
        last_lon: Optional[float],
        last_time: Optional[datetime],
        last_city: Optional[str],
        curr_lat: float,
        curr_lon: float,
        curr_time: datetime,
        curr_city: str
    ) -> Dict[str, Any]:
        """
        Check if traveling from last login location to current location within the time delta
        violates maximum realistic human transit velocity.
        """
        if last_lat is None or last_lon is None or last_time is None:
            return {
                'is_impossible_travel': False,
                'distance_km': 0.0,
                'time_delta_mins': 0.0,
                'velocity_kmh': 0.0,
                'reason': None
            }

        distance_km = cls.haversine_distance(last_lat, last_lon, curr_lat, curr_lon)
        time_delta_seconds = abs((curr_time - last_time).total_seconds())
        time_delta_hours = time_delta_seconds / 3600.0
        time_delta_mins = time_delta_seconds / 60.0

        # If locations are identical or very close (< 50 km), impossible travel is false
        if distance_km < 50.0:
            return {
                'is_impossible_travel': False,
                'distance_km': round(distance_km, 1),
                'time_delta_mins': round(time_delta_mins, 1),
                'velocity_kmh': 0.0,
                'reason': None
            }

        # Calculate transit velocity in km/h
        effective_hours = max(time_delta_hours, 0.0001)
        velocity_kmh = distance_km / effective_hours

        # Impossible travel threshold check:
        # Distance > 300 km AND Speed > 800 km/h (Commercial aircraft max cruise velocity)
        is_impossible = (distance_km >= 300.0) and (velocity_kmh > cls.MAX_COMMERCIAL_FLIGHT_SPEED_KMH)

        reason = None
        if is_impossible:
            reason = (
                f"Impossible Travel Detected: Ingress shifted {distance_km:,.0f} km "
                f"from {last_city or 'Prior Location'} to {curr_city} in {time_delta_mins:.1f} minutes "
                f"(Implied Velocity: {velocity_kmh:,.0f} km/h - Commercial Jet Limit: 800 km/h)."
            )

        return {
            'is_impossible_travel': is_impossible,
            'distance_km': round(distance_km, 1),
            'time_delta_mins': round(time_delta_mins, 1),
            'velocity_kmh': round(velocity_kmh, 1),
            'reason': reason
        }
