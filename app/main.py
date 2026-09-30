from app.core.ai_orchestrator import AIOrchestrator


def main():

    print("\n========================================")
    print("          VAJRA SECURITY AI")
    print("========================================")

    url = input("\nEnter URL: ")

    orchestrator = AIOrchestrator()

    result = orchestrator.analyze_url(url)

    print("\n---------- SECURITY ANALYSIS ----------")

    print("URL:", result["input"])

    print("\nRisk Score:", result["risk_score"])
    print("Risk Level:", result["risk_level"])

    print("Threat:", result["threat"])
    print("Confidence:", result["confidence"], "%")

    print("\nRecommended Action:", result["action"])
    print("Severity:", result["severity"])

    print("\nExplanation:")
    print(result["message"])

    print("\n------------- AI ENGINE ---------------")

    print("Model:", result["ai_model"])
    print("Runtime:", result["ai_runtime"])
    print("Status:", result["ai_status"])
    print("Inference Latency:", result["ai_latency_ms"], "ms")

    print("\n========================================")


if __name__ == "__main__":
    main()