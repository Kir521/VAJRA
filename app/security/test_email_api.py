import requests
import json

BASE = "http://127.0.0.1:5000"


def test_safe():
    payload = {
        "subject": "Meeting Reminder",
        "message": "The project meeting is scheduled for tomorrow."
    }

    r = requests.post(
        f"{BASE}/api/analyze-email",
        json=payload,
        timeout=10
    )

    print("\nSAFE EMAIL")
    print("HTTP:", r.status_code)

    data = r.json()

    print("TYPE:", data.get("type"))
    print("RISK:", data.get("security", {}).get("risk_level"))
    print("SCORE:", data.get("security", {}).get("risk_score"))
    print("THREAT:", data.get("security", {}).get("threat"))
    print("ACTION:", data.get("security", {}).get("action"))

    assert r.status_code == 200
    assert data.get("type") == "email"


def test_phishing():
    payload = {
        "subject": "URGENT: Account Verification",
        "message": (
            "Urgent! Your account will be suspended. "
            "Verify your account immediately and enter your "
            "password and OTP at "
            "https://user@example.com:8080/login"
        )
    }

    r = requests.post(
        f"{BASE}/api/analyze-email",
        json=payload,
        timeout=10
    )

    print("\nPHISHING EMAIL")
    print("HTTP:", r.status_code)

    data = r.json()

    print("TYPE:", data.get("type"))
    print("RISK:", data.get("security", {}).get("risk_level"))
    print("SCORE:", data.get("security", {}).get("risk_score"))
    print("THREAT:", data.get("security", {}).get("threat"))
    print("ACTION:", data.get("security", {}).get("action"))
    print("INCIDENT:", data.get("incident"))
    print("SCAN:", data.get("scan"))

    assert r.status_code == 200
    assert data.get("type") == "email"
    assert data.get("security", {}).get("risk_score", 0) >= 70
    assert data.get("security", {}).get("action") == "BLOCK"


def main():
    test_safe()
    test_phishing()

    print("\nEMAIL API TEST: PASS")


if __name__ == "__main__":
    main()
