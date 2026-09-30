from app.security.file_security_pipeline import (
    FileSecurityPipeline
)


def main():

    pipeline = FileSecurityPipeline()

    result = pipeline.analyze(
        "README.md"
    )

    print("\n===== FILE ANALYSIS =====")
    print(result["file_analysis"])

    print("\n===== SECURITY EVIDENCE =====")
    print(result["evidence"])


if __name__ == "__main__":
    main()