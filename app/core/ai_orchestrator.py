from app.core.risk_engine import RiskEngine
from app.core.threat_classifier import ThreatClassifier
from app.core.decision_engine import DecisionEngine
from app.security.url_guardian import URLGuardian
from app.models.qwen_vl_model import QwenVLModel
from app.models.ai_backend import AIBackend
from app.models.model_manager import ModelManager
from app.models.inference_manager import InferenceManager
from app.models.backend_manager import BackendManager


class AIOrchestrator:

    def __init__(self):

        self.url_guardian = URLGuardian()

        self.risk_engine = RiskEngine()
        self.threat_classifier = ThreatClassifier()
        self.decision_engine = DecisionEngine()

        self.ai_model = QwenVLModel()
        self.ai_backend = AIBackend()

        self.model_manager = ModelManager()

        self.backend_manager = BackendManager()

        self.inference_manager = InferenceManager(
            self.model_manager,
            self.backend_manager
        )

    # =========================================
    # URL ANALYSIS
    # =========================================

    def analyze_url(self, url):

        signals = self.url_guardian.analyze(url)

        risk_result = self.risk_engine.calculate_risk(
            signals
        )

        classification = self.threat_classifier.classify(
            signals
        )

        decision = self.decision_engine.decide(
            risk_result["risk_score"]
        )

        ai_result = self.inference_manager.run(
            input_type="url",
            data={
                "url": url,
                "signals": signals
            }
        )

        ai_analysis = self._build_ai_analysis(
            target=url,
            signals=signals,
            risk_result=risk_result,
            classification=classification,
            decision=decision,
            ai_result=ai_result
        )

        return {
            "input": url,

            "signals": signals,

            "risk_score": risk_result["risk_score"],

            "risk_level": risk_result["risk_level"],

            "threat": classification["threat"],

            "confidence": classification["confidence"],

            "action": decision["action"],

            "severity": decision["severity"],

            "message": decision["message"],

            "ai_model": ai_result["model"],

            "ai_runtime": ai_result["runtime"],

            "ai_status": ai_result["status"],

            "ai_backend": ai_result["backend"],

            "ai_backend_status": ai_result["backend_status"],

            "ai_analysis": ai_analysis,

            "ai_latency_ms": ai_result["latency_ms"]
        }

    # =========================================
    # FILE ANALYSIS
    # =========================================

    def analyze_file(
        self,
        file_path,
        file_analysis,
        security=None,
        risk_result=None,
        classification=None,
        decision=None
    ):

        # -----------------------------------------
        # Calculate missing security information
        # -----------------------------------------

        signals = {
            "executable_file": file_analysis.get(
                "executable_file",
                False
            ),

            "double_extension": file_analysis.get(
                "double_extension",
                False
            ),

            "large_file": file_analysis.get(
                "large_file",
                False
            ),

            "hidden_file": file_analysis.get(
                "hidden_file",
                False
            )
        }

        if risk_result is None:

            risk_result = self.risk_engine.calculate_risk(
                signals
            )

        if classification is None:

            classification = (
                self.threat_classifier.classify(
                    signals
                )
            )

        if decision is None:

            decision = self.decision_engine.decide(
                risk_result["risk_score"]
            )

        # -----------------------------------------
        # Prepare AI inference
        # -----------------------------------------

        ai_result = self.inference_manager.run(
            input_type="file",
            data={
                "file": file_path,
                "file_analysis": file_analysis,
                "signals": signals,
                "security": security,
                "risk": risk_result,
                "threat": classification,
                "decision": decision
            }
        )

        # -----------------------------------------
        # Build explanation
        # -----------------------------------------

        indicators = []

        if signals.get("executable_file"):
            indicators.append(
                "Potentially executable or script file"
            )

        if signals.get("double_extension"):
            indicators.append(
                "Suspicious double file extension"
            )

        if signals.get("large_file"):
            indicators.append(
                "Large file detected"
            )

        if signals.get("hidden_file"):
            indicators.append(
                "Hidden file detected"
            )

        backend_status = ai_result.get(
            "backend_status",
            "unknown"
        )

        model_execution = (
            ai_result
            .get("backend_response", {})
            .get("execution", "not_executed")
        )

        if backend_status == "geniex_ready":

            analysis_status = "model_ready_not_executed"

            explanation = (
                "The selected GenieX backend and "
                "Qwen3.5-2B model are configured, "
                "but an actual model inference result "
                "has not been produced yet."
            )

        else:

            analysis_status = "rule_based_security_analysis"

            explanation = (
                "This file assessment is based on "
                "VAJRA's current file-security rules "
                "and classifiers. No actual AI model "
                "inference was performed."
            )

        ai_analysis = {
            "status": analysis_status,

            "target": file_path,

            "file_type": file_analysis.get(
                "extension",
                ""
            ),

            "sha256": file_analysis.get(
                "sha256"
            ),

            "threat": classification["threat"],

            "risk_score": risk_result["risk_score"],

            "risk_level": risk_result["risk_level"],

            "confidence": classification["confidence"],

            "indicators": indicators,

            "recommended_action": decision["action"],

            "explanation": explanation,

            "model_execution": model_execution
        }

        return {
            "file": file_path,

            "signals": signals,

            "risk": risk_result,

            "threat": classification,

            "decision": decision,

            "model": ai_result.get(
                "model",
                "VAJRA AI"
            ),

            "runtime": ai_result.get(
                "runtime",
                "development"
            ),

            "status": ai_result.get(
                "status",
                "ready"
            ),

            "backend": ai_result.get(
                "backend",
                "development"
            ),

            "backend_status": backend_status,

            "ai_analysis": ai_analysis,

            "inference": ai_result
        }

    # =========================================
    # BUILD URL AI ANALYSIS
    # =========================================

    def _build_ai_analysis(
        self,
        target,
        signals,
        risk_result,
        classification,
        decision,
        ai_result
    ):

        indicators = []

        if signals.get("malicious_url"):
            indicators.append(
                "Malicious URL indicator"
            )

        if signals.get("suspicious_domain"):
            indicators.append(
                "Suspicious domain indicator"
            )

        if signals.get("credential_request"):
            indicators.append(
                "Credential request detected"
            )

        if signals.get("suspicious_redirect"):
            indicators.append(
                "Suspicious redirect indicator"
            )

        if signals.get("known_threat"):
            indicators.append(
                "Known threat indicator"
            )

        if signals.get("ip_address_url"):
            indicators.append(
                "IP address used instead of domain"
            )

        if signals.get("suspicious_tld"):
            indicators.append(
                "Suspicious top-level domain"
            )

        if signals.get("encoded_url"):
            indicators.append(
                "Encoded URL content detected"
            )

        if signals.get("many_subdomains"):
            indicators.append(
                "Unusually deep subdomain structure"
            )

        if signals.get("url_too_long"):
            indicators.append(
                "URL is unusually long"
            )

        model_execution = (
            ai_result
            .get("backend_response", {})
            .get("execution", "not_executed")
        )

        if ai_result["backend_status"] == "geniex_ready":

            analysis_status = "model_ready_not_executed"

            explanation = (
                "The selected GenieX backend and "
                "Qwen3.5-2B model are configured, "
                "but an actual model inference result "
                "has not been produced yet."
            )

        else:

            analysis_status = "rule_based_security_analysis"

            explanation = (
                "This result is based on VAJRA's "
                "current security rules and classifiers. "
                "No actual AI model inference was performed."
            )

        return {
            "status": analysis_status,

            "target": target,

            "threat": classification["threat"],

            "risk_score": risk_result["risk_score"],

            "risk_level": risk_result["risk_level"],

            "confidence": classification["confidence"],

            "indicators": indicators,

            "recommended_action": decision["action"],

            "explanation": explanation,

            "model_execution": model_execution
        }

    # =========================================
    # BACKEND
    # =========================================

    def set_backend(self, backend_name):

        self.backend_manager.set_backend(
            backend_name
        )

    # =========================================
    # BACKEND STATUS
    # =========================================

    def get_backend_status(self):

        return self.backend_manager.get_status()