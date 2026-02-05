from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import time
import threading
import requests


@dataclass
class AuthorityProfile:
    name: str
    type: str  # "BANK" | "GOVT"
    official_domains: List[str]
    official_channels: List[str]
    never_asks: List[str]
    never_requests: List[str]
    last_refreshed: float = 0.0


class AuthorityFetcher:
    """Simple in-memory authority profile fetcher with TTL and seeded profiles.

    This is a lightweight implementation for Phase 1.5. It can be extended to
    fetch live pages for verification and to refresh cached entries.
    """

    _cache: Dict[str, AuthorityProfile] = {}
    _lock = threading.Lock()
    _ttl_seconds = 6 * 60 * 60  # 6 hours by default

    # Seeded profiles for common authorities
    _seeded: Dict[str, AuthorityProfile] = {
        "SBI": AuthorityProfile(
            name="SBI",
            type="BANK",
            official_domains=["sbi.co.in", "onlinesbi.sbi"],
            official_channels=["SMS", "EMAIL", "APP"],
            never_asks=["otp", "pin", "cvv", "password", "secret code"],
            never_requests=["upi collect", "remote access"]
        ),
        "HDFC": AuthorityProfile(
            name="HDFC",
            type="BANK",
            official_domains=["hdfcbank.com"],
            official_channels=["SMS", "EMAIL", "APP"],
            never_asks=["otp", "pin", "cvv"],
            never_requests=["upi collect", "remote access"]
        ),
        "RBI": AuthorityProfile(
            name="RBI",
            type="GOVT",
            official_domains=["rbi.org.in"],
            official_channels=["NOTICE", "EMAIL"],
            never_asks=["otp", "account password"],
            never_requests=["fine payment via upi"]
        ),
        "POLICE": AuthorityProfile(
            name="POLICE",
            type="GOVT",
            official_domains=[],
            official_channels=["CALL", "NOTICE"],
            never_asks=["otp", "bank account"],
            never_requests=["send money immediately", "upi fine payment"]
        )
    }

    @classmethod
    def get_profile(cls, name: str) -> Optional[AuthorityProfile]:
        if not name:
            return None
        key = name.strip().upper()
        with cls._lock:
            # Return cached and fresh
            existing = cls._cache.get(key)
            if existing and (time.time() - existing.last_refreshed) < cls._ttl_seconds:
                return existing

        # Try seeded
        seed = cls._seeded.get(key)
        if seed:
            seed.last_refreshed = time.time()
            with cls._lock:
                cls._cache[key] = seed
            return seed

        # Fallback: attempt lightweight discovery (best-effort)
        profile = cls._discover_profile(key)
        if profile:
            profile.last_refreshed = time.time()
            with cls._lock:
                cls._cache[key] = profile
        return profile

    @classmethod
    def _discover_profile(cls, key: str) -> Optional[AuthorityProfile]:
        # Very lightweight heuristic: try common domain patterns
        try_domains = [f"{key.lower()}.com", f"{key.lower()}.co.in", f"{key.lower()}.org"]
        for d in try_domains:
            try:
                url = f"https://{d}"
                r = requests.get(url, timeout=3)
                if r.status_code == 200:
                    # Create a minimal profile
                    return AuthorityProfile(
                        name=key,
                        type="BANK" if any(k in key for k in ["BANK", "SBI", "HDFC", "ICICI"]) else "GOVT",
                        official_domains=[d],
                        official_channels=["WEBSITE"],
                        never_asks=["otp", "password"],
                        never_requests=[]
                    )
            except Exception:
                continue
        return None

    @classmethod
    def refresh_profile(cls, name: str) -> Optional[AuthorityProfile]:
        # Force refresh (clear cache and re-discover)
        if not name:
            return None
        key = name.strip().upper()
        with cls._lock:
            cls._cache.pop(key, None)
        return cls.get_profile(key)

    @classmethod
    def seeded_names(cls) -> List[str]:
        return list(cls._seeded.keys())
