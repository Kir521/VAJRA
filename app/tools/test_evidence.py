from app.tools.evidence_collector import EvidenceCollector


collector = EvidenceCollector()

evidence = collector.create_evidence(
    source="URL Guardian",
    category="URL Analysis",
    target="https://example.com",
    data={
        "https": True,
        "suspicious_domain": False,
        "credential_request": False
    },
    severity="LOW"
)

print("\n===== VAJRA EVIDENCE =====")

for key, value in evidence.items():
    print(f"{key}: {value}")