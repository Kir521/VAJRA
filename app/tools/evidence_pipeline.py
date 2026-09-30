from app.tools.evidence_collector import EvidenceCollector


class EvidencePipeline:

    def __init__(self):

        self.collector = EvidenceCollector()

    def add_evidence(
        self,
        source,
        category,
        target,
        data,
        severity="INFO"
    ):

        evidence = self.collector.create_evidence(
            source=source,
            category=category,
            target=target,
            data=data,
            severity=severity
        )

        return evidence

    def build_report(self, evidence_items):

        return {
            "total_evidence": len(evidence_items),
            "evidence": evidence_items
        }