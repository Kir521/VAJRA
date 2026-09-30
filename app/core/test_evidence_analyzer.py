from app.core.evidence_analyzer import EvidenceAnalyzer


def main():

    print("\n===== VAJRA EVIDENCE ANALYZER TEST =====")

    analyzer = EvidenceAnalyzer()

    evidence = [
        {
            "source": "URLGuardian",
            "category": "url_analysis",
            "target": "http://example.com/login",
            "severity": "HIGH",
            "data": {
                "malicious_url": True,
                "suspicious_domain": True,
                "credential_request": True,
                "suspicious_redirect": False,
                "known_threat": False
            }
        }
    ]

    result = analyzer.analyze(evidence)

    print("\nSignals:")
    print(result["signals"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nRisk Level:")
    print(result["risk_level"])

    print("\nThreat:")
    print(result["threat"])

    print("\nConfidence:")
    print(result["confidence"])

    print("\nAction:")
    print(result["action"])

    print("\nSeverity:")
    print(result["severity"])

    print("\nMessage:")
    print(result["message"])


if __name__ == "__main__":
    main()