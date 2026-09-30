from app.security.security_analyzer import SecurityAnalyzer


def main():

    print("\n===== VAJRA END-TO-END SECURITY TEST =====")

    analyzer = SecurityAnalyzer()

    url = "http://192.168.1.100/login"

    result = analyzer.analyze_url(url)

    print("\nURL:", result["url"])

    print("\n--- SECURITY SIGNALS ---")
    print(result["signals"])

    print("\n--- RISK ---")
    print("Score:", result["risk_score"])
    print("Level:", result["risk_level"])

    print("\n--- THREAT ---")
    print("Threat:", result["threat"])
    print("Confidence:", result["confidence"])

    print("\n--- DECISION ---")
    print("Action:", result["action"])
    print("Severity:", result["severity"])
    print("Message:", result["message"])

    print("\n--- AI ---")
    print("Model:", result["ai"]["model"])
    print("Runtime:", result["ai"]["runtime"])
    print("Status:", result["ai"]["status"])


if __name__ == "__main__":
    main()