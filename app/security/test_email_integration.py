from app.security.email_message_guardian import EmailMessageGuardian


def main():
    guardian = EmailMessageGuardian()

    tests = [
        {
            "name": "SAFE",
            "subject": "Meeting reminder",
            "message": "The project meeting is scheduled for tomorrow."
        },
        {
            "name": "PHISHING",
            "subject": "URGENT: Verify your account",
            "message": (
                "Urgent! Your account will be suspended. "
                "Verify your account immediately and enter your password "
                "and OTP at https://user@example.com:8080/login"
            )
        },
        {
            "name": "FINANCIAL",
            "subject": "Payment required",
            "message": (
                "Send money immediately to claim your reward "
                "and provide your bank details."
            )
        }
    ]

    for test in tests:
        result = guardian.analyze(
            test["message"],
            test["subject"]
        )

        print("\nTEST:", test["name"])
        print("SCORE:", result["risk_score"])
        print("LEVEL:", result["risk_level"])
        print("THREAT:", result["threat"])
        print("ACTION:", result["action"])
        print("SIGNALS:", result["signals"])

    print("\nEMAIL INTEGRATION TEST COMPLETE")


if __name__ == "__main__":
    main()
