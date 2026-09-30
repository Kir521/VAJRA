from app.core.security_engine import SecurityEngine


def test_analyze_file_creates_scan_record():
    engine = SecurityEngine()
    result = engine.analyze_file("README.md")

    assert result["type"] == "file"
    assert result["target"] == "README.md"
    assert result["scan"]["type"] == "FILE"
    assert result["scan"]["target"] == "README.md"
    assert result["scan"]["id"] == engine.scan_id


def main():

    print("\n===== VAJRA SECURITY ENGINE TEST =====")

    engine = SecurityEngine()

    # URL test
    print("\n--- URL ANALYSIS ---")

    url_result = engine.analyze_url(
        "http://192.168.1.100/login"
    )

    print("Risk Score:",
          url_result["security"]["risk_score"])

    print("Risk Level:",
          url_result["security"]["risk_level"])

    print("Threat:",
          url_result["security"]["threat"])

    print("Action:",
          url_result["security"]["action"])

    # File test
    print("\n--- FILE ANALYSIS ---")

    file_result = engine.analyze_file(
        "README.md"
    )

    print("File:",
          file_result["target"])

    print("SHA-256:",
          file_result["file_analysis"]["sha256"])

    print("Severity:",
          file_result["file_analysis"]["severity"])

    # Privacy test
    print("\n--- PRIVACY ANALYSIS ---")

    privacy_result = engine.analyze_privacy()

    print("Privacy Risk:",
          privacy_result["security"]["risk_level"])


if __name__ == "__main__":
    main()