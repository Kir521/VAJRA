from app.core.risk_engine import RiskEngine
from app.core.threat_classifier import ThreatClassifier
from app.core.decision_engine import DecisionEngine


class EvidenceAnalyzer:

    def __init__(self):

        self.risk_engine = RiskEngine()
        self.threat_classifier = ThreatClassifier()
        self.decision_engine = DecisionEngine()

    def analyze(self, evidence_items):

        signals = self._extract_signals(
            evidence_items
        )

        risk = self.risk_engine.calculate_risk(
            signals
        )

        classification = (
            self.threat_classifier.classify(signals)
        )

        decision = self.decision_engine.decide(
            risk["risk_score"]
        )

        return {
            "signals": signals,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "threat": classification["threat"],
            "confidence": classification["confidence"],
            "action": decision["action"],
            "severity": decision["severity"],
            "message": decision["message"]
        }

    def _extract_signals(self, evidence_items):

        signals = {
            "malicious_url": False,
            "suspicious_domain": False,
            "credential_request": False,
            "suspicious_redirect": False,
            "known_threat": False
        }

        for evidence in evidence_items:

            data = evidence.get("data", {})

            if not isinstance(data, dict):
                continue

            # URL Guardian signals
            for key in signals:

                if data.get(key) is True:
                    signals[key] = True

        return signals