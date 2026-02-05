"""
Scam Detection Service - Implements PRD Phase 1 detection logic.
Supports 13 scam categories, keyword analysis, and rule-based validation.
"""

import re
from typing import Tuple, Optional, Dict, List

from .authority_fetcher import AuthorityFetcher

# Bank rules - what legitimate banks never ask for
BANK_RULES = {
    "SBI": {
        "never_asks": ["OTP", "PIN", "CVV", "password", "secret code"],
        "never_requests": ["UPI collect", "remote access", "teamviewer", "anydesk"]
    },
    "HDFC": {
        "never_asks": ["OTP", "PIN", "CVV", "password"],
        "never_requests": ["UPI collect", "remote access"]
    },
    "ICICI": {
        "never_asks": ["OTP", "PIN", "CVV"],
        "never_requests": ["UPI collect", "remote access"]
    },
    "AXIS": {
        "never_asks": ["OTP", "PIN", "CVV"],
        "never_requests": ["UPI collect"]
    },
    "RBI": {
        "never_asks": ["OTP", "account details"],
        "never_requests": ["fine payment via UPI"]
    }
}

# Government rules - what authorities never ask for
GOVT_RULES = {
    "POLICE": {
        "never": ["arrest threats on call", "UPI fine payment", "send money immediately"],
        "never_asks": ["OTP", "bank account"]
    },
    "INCOME_TAX": {
        "never": ["immediate payment threats", "UPI payment"],
        "never_asks": ["PAN pin", "social security"]
    },
    "RBI_OFFICIAL": {
        "never": ["account verification payments"],
        "never_asks": ["account password"]
    }
}

# Scam category keywords mapping
SCAM_KEYWORDS = {
    "Bank / KYC / OTP Scam": {
        "keywords": ["otp", "pin", "cvv", "kyc", "verification", "blocked", "suspended", "account will be locked", "confirm identity"],
        "score": 50,
        "patterns": [r"otp.*\d+", r"pin.*\d+", r"cvv.*\d+"]
    },
    "Fake Government / Police Scam": {
        "keywords": ["police", "fir", "arrest", "warrant", "income tax", "fine", "penalty", "rbi"],
        "score": 40,
        "patterns": [r"case.*filed", r"arrest warrant", r"government"]
    },
    "UPI Refund / Collect Scam": {
        "keywords": ["upi", "refund", "collect", "transfer", "paytm", "googlepay", "phonepe"],
        "score": 35,
        "patterns": [r"upi.*@\w+", r"\d{10}@\w+"]
    },
    "Job / Internship Scam": {
        "keywords": ["job", "internship", "position", "hire", "salary", "work from home", "data entry"],
        "score": 30,
        "patterns": [r"rs\.?\s*\d+", r"salary.*\d+"]
    },
    "Investment / Crypto Scam": {
        "keywords": ["invest", "bitcoin", "crypto", "forex", "stock", "profit", "returns", "guaranteed"],
        "score": 40,
        "patterns": [r"profit.*%", r"return.*guarantee"]
    },
    "Phishing Link Scam": {
        "keywords": ["click", "link", "download", "update", "verify", "confirm"],
        "score": 45,
        "patterns": [r"https?://[^\s]+", r"bit\.ly", r"tinyurl"]
    },
    "Delivery / Courier Scam": {
        "keywords": ["delivery", "courier", "package", "shipment", "tracking", "customs"],
        "score": 25,
        "patterns": [r"tracking.*\w+", r"shipment.*\w+"]
    },
    "Romance Scam": {
        "keywords": ["love", "sweetheart", "marriage", "relationship", "need money"],
        "score": 35,
        "patterns": []
    },
    "Lottery / Prize Scam": {
        "keywords": ["lottery", "prize", "won", "congratulations", "claim", "reward"],
        "score": 40,
        "patterns": [r"won.*rs\.?\s*\d+"]
    },
    "Remote Access Scam": {
        "keywords": ["teamviewer", "anydesk", "screen", "remote", "access", "control"],
        "score": 50,
        "patterns": [r"teamviewer|anydesk"]
    },
    "Fake Customer Care Scam": {
        "keywords": ["customer care", "support", "amazon", "flipkart", "call", "helpline"],
        "score": 30,
        "patterns": []
    },
    "Missed Call Scam": {
        "keywords": ["missed call", "call back", "callback", "dial"],
        "score": 20,
        "patterns": [r"\+91\d{10}"]
    },
    "Fake Course / Certificate Scam": {
        "keywords": ["course", "certificate", "diploma", "training", "degree", "enroll"],
        "score": 25,
        "patterns": []
    }
}


class ScamDetector:
    """PRD-compliant scam detection engine."""

    @staticmethod
    def detect(text: str) -> Tuple[bool, Optional[str], int, Dict[str, List[str]]]:
        """
        Detect scam intent, classify type, calculate confidence, extract intelligence.

        Args:
            text: Incoming message text

        Returns:
            (scamDetected, scamType, scamScore, extractedIntelligence)
        """
        text_lower = text.lower()
        score = 0
        scam_type = None
        intel = {
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "bankAccounts": [],
            "suspiciousKeywords": [],
            "authorityProfile": None
        }

        # Step 1: Category matching and keyword scoring
        category_scores = {}
        for category, details in SCAM_KEYWORDS.items():
            cat_score = 0
            matched_keywords = []

            # Keyword matching
            for keyword in details["keywords"]:
                if keyword in text_lower:
                    cat_score += 10
                    matched_keywords.append(keyword)

            # Pattern matching
            for pattern in details.get("patterns", []):
                if re.search(pattern, text_lower):
                    cat_score += 15

            if cat_score > 0:
                cat_score += details["score"]
                category_scores[category] = cat_score

            if matched_keywords and cat_score > 0:
                intel["suspiciousKeywords"].extend(matched_keywords[:3])

        # Select highest scoring category
        if category_scores:
            scam_type = max(category_scores, key=category_scores.get)
            score = min(100, category_scores[scam_type])

        # Step 2: Extract intelligence
        ScamDetector._extract_intelligence(text, intel)

        # Step 3: Authority-aware rule validation (Phase 1.5)
        # Extract claimed authority (lightweight keyword match) and fetch profile
        claimed = ScamDetector._extract_claimed_authority(text_lower)
        if claimed:
            profile = AuthorityFetcher.get_profile(claimed)
            if profile:
                intel["authorityProfile"] = {
                    "name": profile.name,
                    "type": profile.type,
                    "official_domains": profile.official_domains,
                    "official_channels": profile.official_channels,
                    "last_refreshed": profile.last_refreshed,
                }

        # Apply rule validation (uses both static rules and dynamic profile)
        score = ScamDetector._apply_rule_validation(text_lower, scam_type, score, claimed)

        # Determine if scam detected (threshold: 35 or higher)
        scam_detected = score >= 35
        return scam_detected, scam_type if scam_detected else None, score, intel

    @staticmethod
    def _extract_intelligence(text: str, intel: Dict[str, List[str]]) -> None:
        """Extract UPI IDs, phone numbers, links, bank accounts from text."""
        # UPI IDs (simple pattern)
        upi_pattern = r"[\w.\-]+@[a-zA-Z]+"
        upi_matches = re.findall(upi_pattern, text)
        intel["upiIds"].extend(list(set(upi_matches))[:5])

        # Phone numbers (10-digit Indian)
        phone_pattern = r"\b\d{10}\b"
        phone_matches = re.findall(phone_pattern, text)
        intel["phoneNumbers"].extend(list(set(phone_matches))[:5])

        # Phishing links
        link_pattern = r"https?://[^\s]+"
        link_matches = re.findall(link_pattern, text)
        intel["phishingLinks"].extend(list(set(link_matches))[:5])

        # Bank account numbers (rough pattern: 10-16 digits)
        account_pattern = r"\b\d{10,16}\b"
        account_matches = re.findall(account_pattern, text)
        intel["bankAccounts"].extend(list(set(account_matches))[:5])

    @staticmethod
    def _apply_rule_validation(text_lower: str, scam_type: Optional[str], base_score: int, claimed_authority: Optional[str] = None) -> int:
        """
        Apply bank/government rule validation to boost scam score if violations detected.
        """
        score = base_score

        # Check for bank rule violations
        for bank, rules in BANK_RULES.items():
            if bank.lower() in text_lower or "bank" in text_lower:
                for forbidden in rules["never_asks"]:
                    if forbidden.lower() in text_lower:
                        score += 30
                        break

                for forbidden in rules["never_requests"]:
                    if forbidden.lower() in text_lower:
                        score += 25
                        break

        # Check for government rule violations
        for authority, rules in GOVT_RULES.items():
            auth_keywords = authority.lower().split("_")
            if any(kw in text_lower for kw in auth_keywords):
                for forbidden in rules.get("never", []):
                    if forbidden.lower() in text_lower:
                        score += 40
                        break

                for forbidden in rules.get("never_asks", []):
                    if forbidden.lower() in text_lower:
                        score += 30
                        break

        # Dynamic profile-based checks (Phase 1.5)
        if claimed_authority:
            profile = AuthorityFetcher.get_profile(claimed_authority)
            if profile:
                # check never_asks and never_requests from dynamic profile
                for forbidden in profile.never_asks:
                    if forbidden.lower() in text_lower:
                        score += 30
                        break

                for forbidden in profile.never_requests:
                    if forbidden.lower() in text_lower:
                        score += 25
                        break

        return min(100, score)

    @staticmethod
    def _extract_claimed_authority(text_lower: str) -> Optional[str]:
        """Lightweight extraction of claimed authority from message text."""
        # Check known bank keys
        candidates = []
        for bank in BANK_RULES.keys():
            if bank.lower() in text_lower:
                candidates.append(bank)

        # Check known govt keys
        for auth in GOVT_RULES.keys():
            if auth.lower().replace("_", " ") in text_lower or auth.lower() in text_lower:
                candidates.append(auth)

        # Check seeded authority fetcher names as fallback
        try:
            for name in AuthorityFetcher.seeded_names():
                if name.lower() in text_lower and name not in candidates:
                    candidates.append(name)
        except Exception:
            pass

        if candidates:
            # Prefer the first candidate
            return candidates[0]
        return None
