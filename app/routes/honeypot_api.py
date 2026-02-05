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


class HoneypotMessageResponse(BaseModel):
    status: str
    reply: str
    scamDetected: bool
    scamType: Optional[str]
    scamScore: int
    extractedIntelligence: Optional[Dict[str, List[str]]] = Field(default_factory=dict)


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

    return HoneypotMessageResponse(
        status="success",
        reply=reply,
        scamDetected=scamDetected,
        scamType=scamType,
        scamScore=scamScore,
        extractedIntelligence=extracted
    )
