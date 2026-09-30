from datetime import datetime


class EvidenceCollector:

    def create_evidence(
        self,
        source,
        category,
        target,
        data,
        severity="INFO"
    ):

        evidence = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "category": category,
            "target": target,
            "severity": severity,
            "data": data
        }

        return evidence