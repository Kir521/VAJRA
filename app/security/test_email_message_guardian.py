from app.security.email_message_guardian import EmailMessageGuardian


def run_test(name, subject, message):
    guardian = EmailMessageGuardian()
    result = guardian.analyze(message, subject)

    print("\n========================================")
    print(name)
    print("========================================")
    print("Risk Score :", result["risk_score"])
    print("Risk Level :", result["risk_level"])
    print("Threat     :", result["threat"])
    print("Action     :", result["action"])
    print("Confidence :", result["confidence"])
    print("Signals    :", result["signals"])
    print("Findings   :", result["findings"])

    return result


def main():
    safe = run_test(
        "SAFE MESSAGE",
        "Meeting reminder",
        "Hi, the project meeting is scheduled for tomorrow at 10 AM."
    )

    phishing = run_test(
        "PHISHING MESSAGE",
        "URGENT: Verify your account",
        "Urgent! Your account will be suspended. "
        "Verify your account immediately and enter your password "
        "and OTP using https://user@example.com:8080/login"
    )

    financial = run_test(
        "FINANCIAL SCAM MESSAGE",
        "Payment required",
        "Your refund is ready. Send money immediately to claim your reward "
        "and provide your bank details."
    )

    attachment = run_test(
        "SUSPICIOUS ATTACHMENT",
        "Invoice attached",
        "Please review the invoice.exe attachment immediately."
    )

    assert safe["risk_level"] == "LOW"
    assert phishing["signals"]["urgency_language"] is True
    assert phishing["signals"]["credential_request"] is True
    assert phishing["signals"]["suspicious_link"] is True
    assert phishing["signals"]["social_engineering"] is True
    assert financial["signals"]["financial_request"] is True
    assert attachment["signals"]["suspicious_attachment"] is True

    print("\n========================================")
    print("ALL EMAIL/MESSAGE GUARDIAN TESTS PASSED")
    print("========================================")


if __name__ == "__main__":
    main()
