from app.services.scam_detector import ScamDetector

msgs = [
    'SBI: Your account will be blocked, send OTP to 9876543210',
    'HDFC bank alert: please share your OTP to secure account',
    'RBI notice: verify account by sending password',
    'Some normal chat message, hello'
]

for m in msgs:
    detected, scam_type, score, intel = ScamDetector.detect(m)
    print(f"Message: {m}")
    print(f" Detected: {detected}, Type: {scam_type}, Score: {score}")
    print(f" Authority Profile: {intel.get('authorityProfile')}")
    print()
