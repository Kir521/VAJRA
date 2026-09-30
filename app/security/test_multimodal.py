from app.models.model_manager import ModelManager
from app.security.multimodal_analyzer import (
    MultimodalSecurityAnalyzer
)


def main():

    print("\n===== VAJRA MULTIMODAL SECURITY TEST =====")

    model_manager = ModelManager()

    analyzer = MultimodalSecurityAnalyzer(
        model_manager
    )

    result = analyzer.analyze(
        text="Your account has been suspended. Verify immediately.",
        url="https://example.com/login",
        evidence={
            "source": "test",
            "category": "phishing",
            "severity": "medium"
        }
    )

    print("\nModule:", result["module"])
    print("Input Type:", result["input_type"])
    print("Model:", result["model"])
    print("Runtime:", result["runtime"])
    print("Status:", result["status"])
    print("Analysis:", result["analysis"])
    print("Latency:", result["latency_ms"], "ms")


if __name__ == "__main__":
    main()