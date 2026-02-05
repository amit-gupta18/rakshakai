#!/usr/bin/env python
"""Test script for ScamDetector"""
from app.services.scam_detector import ScamDetector

test_msgs = [
    'Your account will be blocked, send OTP to 9876543210',
    'Refund pending, click https://fake.link and enter UPI fraud@upi',
    'Normal message, how are you?',
    'Police case filed, send 10000 via UPI immediately'
]

for msg in test_msgs:
    detected, scam_type, score, intel = ScamDetector.detect(msg)
    print(f"\nText: {msg[:55]}")
    print(f"  Detected: {detected} | Type: {scam_type} | Score: {score}")
    if intel['upiIds'] or intel['phoneNumbers'] or intel['phishingLinks']:
        print(f"  Intel: {intel}")
