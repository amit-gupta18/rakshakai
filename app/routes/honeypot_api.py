"""
Additional honeypot API implementing PRD-style request/response.
Uses the comprehensive ScamDetector service for Phase 1 detection.
"""
from typing import Optional, List, Dict
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends
from app.middleware.auth import verify_api_key
from app.services.scam_detector import ScamDetector

router = APIRouter(prefix="/api/honeypot", tags=["honeypot_api"], dependencies=[Depends(verify_api_key)])


class Message(BaseModel):
    sender: str = Field(..., description="scammer | user")
    text: str = Field(..., description="message text")
    timestamp: Optional[int] = Field(None)


class HoneypotMessageRequest(BaseModel):
    sessionId: Optional[str] = Field(None)
    message: Message = Field(...)
    conversationHistory: Optional[List[Message]] = Field(default_factory=list)
    metadata: Optional[Dict[str, str]] = Field(default=None)


class AuthorityProfile(BaseModel):
    """Represents a single bank/government authority context."""
    name: str
    type: str
    official_domains: List[str]
    official_channels: List[str]
    never_asks: List[str]
    never_requests: List[str]
    last_refreshed: float


class ExtractedIntelligence(BaseModel):
    """Structured intelligence extracted from scam messages."""
    upiIds: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    bankAccounts: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)
    authorityProfile: Optional[AuthorityProfile] = None


class HoneypotMessageResponse(BaseModel):
    status: str
    reply: str
    scamDetected: bool
    scamType: Optional[str]
    scamScore: int
    extractedIntelligence: ExtractedIntelligence


@router.post("/message", response_model=HoneypotMessageResponse)
async def process_message(request: HoneypotMessageRequest):
    """PRD Phase 1 + Phase 2 honeypot endpoint."""
    text = request.message.text
    
    # Phase 1: Scam detection with rule validation
    scamDetected, scamType, scamScore, extracted = ScamDetector.detect(text)

    # Phase 2: Generate persona-guided agent reply
    if scamDetected:
        reply = "I can share the details. What information do you need from my account?"
    else:
        reply = "Thanks for your message — can you tell me more?"

    # Convert extracted dict to ExtractedIntelligence model
    authority_profile = None
    if extracted.get("authorityProfile"):
        authority_profile = AuthorityProfile(**extracted["authorityProfile"])

    intelligence = ExtractedIntelligence(
        upiIds=extracted.get("upiIds", []),
        phoneNumbers=extracted.get("phoneNumbers", []),
        phishingLinks=extracted.get("phishingLinks", []),
        bankAccounts=extracted.get("bankAccounts", []),
        suspiciousKeywords=extracted.get("suspiciousKeywords", []),
        authorityProfile=authority_profile
    )

    return HoneypotMessageResponse(
        status="success",
        reply=reply,
        scamDetected=scamDetected,
        scamType=scamType,
        scamScore=scamScore,
        extractedIntelligence=intelligence
    )
