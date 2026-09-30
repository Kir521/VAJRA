from app.security.url_guardian import URLGuardian
from app.core.risk_engine import RiskEngine
from app.core.threat_classifier import ThreatClassifier
from app.core.decision_engine import DecisionEngine
from app.security.multimodal_analyzer import MultimodalSecurityAnalyzer
from app.models.model_manager import ModelManager


class SecurityAnalyzer:

    def __init__(self):

        self.url_guardian = URLGuardian()
        self.risk_engine = RiskEngine()
        self.threat_classifier = ThreatClassifier()
        self.decision_engine = DecisionEngine()

        self.model_manager = ModelManager()

        self.multimodal_analyzer = (
            MultimodalSecurityAnalyzer(
                self.model_manager
            )
        )

    def analyze_url(self, url):

        # 1. URL analysis
        signals = self.url_guardian.analyze(url)

        # 2. Risk calculation
        risk = self.risk_engine.calculate_risk(
            signals
        )

        # 3. Threat classification
        classification = self.threat_classifier.classify(
            signals
        )

        # 4. Security decision
        decision = self.decision_engine.decide(
            risk["risk_score"]
        )

        # 5. AI analysis
        ai_result = self.multimodal_analyzer.analyze(
            url=url,
            evidence=signals
        )

        return {
            "url": url,

            "signals": signals,

            "risk_score": risk["risk_score"],

            "risk_level": risk["risk_level"],

            "threat": classification["threat"],

            "confidence": classification["confidence"],

            "action": decision["action"],

            "severity": decision["severity"],

            "message": decision["message"],

            "ai": ai_result
        }