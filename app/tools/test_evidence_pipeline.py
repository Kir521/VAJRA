from app.tools.evidence_pipeline import EvidencePipeline


def main():

    print("\n===== VAJRA EVIDENCE PIPELINE TEST =====")

    pipeline = EvidencePipeline()

    evidence = []

    evidence.append(
        pipeline.add_evidence(
            source="FileGuardian",
            category="file_analysis",
            target="README.md",
            data={
                "sha256": "test-hash",
                "extension": ".md"
            },
            severity="LOW"
        )
    )

    evidence.append(
        pipeline.add_evidence(
            source="SecurityTool",
            category="tool_status",
            target="curl",
            data={
                "available": True
            },
            severity="INFO"
        )
    )

    report = pipeline.build_report(
        evidence
    )

    print("\nTotal Evidence:", report["total_evidence"])

    for item in report["evidence"]:

        print("\n--- Evidence ---")
        print("Source:", item["source"])
        print("Category:", item["category"])
        print("Target:", item["target"])
        print("Severity:", item["severity"])


if __name__ == "__main__":
    main()