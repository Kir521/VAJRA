from app.security.privacy_analyzer import PrivacyAnalyzer


def main():

    print("\n===== VAJRA PRIVACY ANALYZER TEST =====")

    analyzer = PrivacyAnalyzer()

    result = analyzer.analyze()

    print("\nSignals:")
    print(result["signals"])

    print("\nFindings:")

    for finding in result["findings"]:
        print("-", finding)

    print("\nPrivacy Risk:")
    print(result["risk_level"])


if __name__ == "__main__":
    main()