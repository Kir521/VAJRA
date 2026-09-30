import inspect
from datetime import datetime

from app.core.storage import Storage
from app.core.ai_orchestrator import AIOrchestrator
from app.core.decision_engine import DecisionEngine
from app.core.evidence_analyzer import EvidenceAnalyzer
from app.core.incident_manager import IncidentManager
from app.core.risk_engine import RiskEngine
from app.core.threat_classifier import ThreatClassifier

from app.security.file_guardian import FileGuardian
from app.security.privacy_analyzer import PrivacyAnalyzer
from app.security.url_guardian import URLGuardian
from app.security.email_message_guardian import EmailMessageGuardian

from app.tools.security_tool_adapter import SecurityToolAdapter


class SecurityEngine:

    def __init__(self):

        self.url_guardian = URLGuardian()
        self.email_message_guardian = EmailMessageGuardian()
        self.file_guardian = FileGuardian()
        self.security_tool_adapter = SecurityToolAdapter()
        self.privacy_analyzer = PrivacyAnalyzer()

        self.evidence_analyzer = EvidenceAnalyzer()
        self.ai_orchestrator = AIOrchestrator()

        self.risk_engine = RiskEngine()
        self.threat_classifier = ThreatClassifier()
        self.decision_engine = DecisionEngine()

        self.incident_manager = IncidentManager()

        self.storage = Storage()

        self.scan_history = self.storage.get_scans(limit=50)

        self.scan_id = self.storage.get_next_scan_id() - 1

    # =========================================
    # AI BACKEND
    # =========================================

    def set_ai_backend(self, backend_name):

        self.ai_orchestrator.set_backend(
            backend_name
        )

    # =========================================
    # AI BACKEND STATUS
    # =========================================

    def get_ai_backend_status(self):

        return (
            self.ai_orchestrator
            .get_backend_status()
        )

    # =========================================
    # URL ANALYSIS
    # =========================================

    def analyze_url(self, url):

        result = self.url_guardian.analyze(
            url
        )

        url_tool_evidence = (
            self.security_tool_adapter
            .collect_url_evidence(url)
        )

        # =========================================
        # EVIDENCE
        # =========================================

        evidence = [
            {
                "source": "URLGuardian",
                "category": "url_analysis",
                "target": url,
                "severity": "INFO",
                "data": result
            },
            {
                "source": "SecurityToolAdapter",
                "category": "tool_evidence",
                "target": url,
                "severity": "INFO",
                "data": url_tool_evidence
            }
        ]

        # =========================================
        # AI / SECURITY ANALYSIS
        # =========================================

        ai_result = (
            self.ai_orchestrator
            .analyze_url(url)
            or {}
        )

        ai_data = ai_result

        # =========================================
        # RISK ENGINE
        # =========================================

        risk_result = (
            self.risk_engine
            .calculate_risk(result)
        )

        # =========================================
        # THREAT CLASSIFICATION
        # =========================================

        classification = (
            self.threat_classifier
            .classify(result)
        )

        # =========================================
        # DECISION ENGINE
        # =========================================

        decision = (
            self.decision_engine
            .decide(
                risk_result["risk_score"]
            )
        )

        # =========================================
        # CONSISTENT SECURITY RESULT
        # =========================================

        security = {

            "risk_score": ai_data.get(
                "risk_score",
                risk_result["risk_score"]
            ),

            "risk_level": ai_data.get(
                "risk_level",
                risk_result["risk_level"]
            ),

            "threat": ai_data.get(
                "threat",
                classification["threat"]
            ),

            "action": ai_data.get(
                "action",
                decision["action"]
            ),

            "confidence": ai_data.get(
                "confidence",
                classification["confidence"]
            ),

            "severity": ai_data.get(
                "severity",
                decision["severity"]
            ),

            "message": ai_data.get(
                "message",
                decision["message"]
            ),

            "signals": result
        }

        # =========================================
        # EXTRACT FINAL RESULT
        # =========================================

        risk_score = int(
            security["risk_score"]
        )

        risk_level = security[
            "risk_level"
        ]

        threat = security[
            "threat"
        ]

        action = security[
            "action"
        ]

        decision_message = security[
            "message"
        ]

        # =========================================
        # CREATE INCIDENT
        # =========================================

        incident = (
            self.incident_manager
            .create_incident(
                incident_type="URL",
                target=url,
                risk_score=risk_score,
                risk_level=risk_level,
                threat=threat,
                action=action,
                evidence=evidence,
                description=decision_message
            )
        )

        # =========================================
        # CREATE SCAN RECORD
        # =========================================

        self.scan_id += 1

        scan_record = {

            "id": self.scan_id,

            "timestamp":
                datetime.now().isoformat(),

            "type": "URL",

            "target": url,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "threat": threat,

            "action": action,

            "ai_model": ai_data.get(
                "ai_model",
                "VAJRA AI"
            ),

            "ai_status": ai_data.get(
                "ai_status",
                "ready"
            )
        }

        # =========================================
        # SAVE SCAN
        # =========================================

        self.storage.save_scan(scan_record)

        self.scan_history = self.storage.get_scans(
            limit=50
        )

        # =========================================
        # FINAL RESPONSE
        # =========================================

        return {

            "type": "url",

            "target": url,

            "signals": result,

            "security": security,

            "ai": ai_result,

            "scan": scan_record,

            "incident": incident
        }

    # =========================================
    # FILE ANALYSIS
    # =========================================


    def analyze_email_message(self, message, subject=""):
        """
        VAJRA Email / Message Security Pipeline.

        Pipeline:
        EmailMessageGuardian
            -> Risk / Threat interpretation
            -> Decision
            -> AI analysis
            -> Incident Center
            -> Scan History
        """

        result = self.email_message_guardian.analyze(
            message,
            subject
        )

        risk_score = int(result.get("risk_score", 0))
        risk_level = result.get("risk_level", "LOW")
        threat = result.get("threat", "LOW RISK")
        action = result.get("action", "ALLOW")
        confidence = int(
            result.get(
                "confidence",
                min(max(risk_score + 15, 20), 99)
            )
        )

        security = {
            "signals": result.get("signals", {}),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threat": threat,
            "confidence": confidence,
            "action": action,
            "severity": risk_level,
            "message": (
                "VAJRA detected significant security risk."
                if risk_score >= 50
                else
                "VAJRA recommends reviewing this message."
                if risk_score >= 25
                else
                "No significant risk detected."
            )
        }

        # ----------------------------------------------------
        # AI
        # ----------------------------------------------------

        ai_result = None

        try:
            if hasattr(self, "inference_manager"):
                ai_result = self.inference_manager.run(
                    input_type="text",
                    data={
                        "email_analysis": result,
                        "subject": subject,
                        "message": message
                    }
                )
            else:
                ai_result = {
                    "status": "not_available"
                }

        except Exception as exc:
            ai_result = {
                "status": "error",
                "message": str(exc)
            }

        # ----------------------------------------------------
        # EVIDENCE
        # ----------------------------------------------------

        evidence = {
            "category": "email_message_analysis",
            "source": "EmailMessageGuardian",
            "target": subject or "email_message",
            "severity": risk_level,
            "data": result
        }

        # ----------------------------------------------------
        # INCIDENT CENTER
        # ----------------------------------------------------

        incident = None

        try:

            manager = getattr(
                self,
                "incident_manager",
                None
            )

            if manager is not None:

                create_method = getattr(
                    manager,
                    "create_incident",
                    None
                )

                if create_method:

                    try:
                        signature = inspect.signature(
                            create_method
                        )

                        params = signature.parameters

                        possible = {
                            "incident_type": "EMAIL",
                            "type": "EMAIL",
                            "target": subject or "email_message",
                            "risk_score": risk_score,
                            "risk_level": risk_level,
                            "threat": threat,
                            "action": action,
                            "description": security["message"],
                            "evidence": [evidence],
                            "status": "OPEN"
                        }

                        kwargs = {
                            k: v
                            for k, v in possible.items()
                            if k in params
                        }

                        incident = create_method(
                            **kwargs
                        )

                    except Exception as exc:
                        incident = {
                            "status": "incident_creation_failed",
                            "error": str(exc)
                        }

        except Exception as exc:
            incident = {
                "status": "incident_creation_failed",
                "error": str(exc)
            }

        # ----------------------------------------------------
        # SCAN HISTORY
        # ----------------------------------------------------

        scan = None

        try:

            candidates = [
                "scan_history",
                "scan_history_manager",
                "scan_manager"
            ]

            manager = None

            for name in candidates:

                candidate = getattr(
                    self,
                    name,
                    None
                )

                if candidate is not None:
                    manager = candidate
                    break

            if manager is not None:

                method = None

                for method_name in [
                    "save_scan",
                    "record_scan",
                    "create_scan",
                    "add_scan"
                ]:

                    candidate = getattr(
                        manager,
                        method_name,
                        None
                    )

                    if callable(candidate):
                        method = candidate
                        break

                if method:

                    signature = inspect.signature(
                        method
                    )

                    params = signature.parameters

                    backend = "development"

                    try:
                        backend = self.get_ai_backend_status().get(
                            "active_backend",
                            "development"
                        )
                    except Exception:
                        pass

                    possible = {
                        "scan_type": "EMAIL",
                        "type": "EMAIL",
                        "target": subject or "email_message",
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "threat": threat,
                        "action": action,
                        "ai_backend": backend,
                        "subject": subject,
                        "message": message
                    }

                    kwargs = {
                        k: v
                        for k, v in possible.items()
                        if k in params
                    }

                    scan = method(
                        **kwargs
                    )

        except Exception as exc:

            scan = {
                "status": "scan_history_unavailable",
                "error": str(exc)
            }

        # ----------------------------------------------------
        # FINAL RESULT
        # ----------------------------------------------------

        return {
            "type": "email",
            "subject": subject,
            "message": message,

            "signals": result.get(
                "signals",
                {}
            ),

            "email_analysis": result,

            "security": security,

            "risk": {
                "risk_score": risk_score,
                "risk_level": risk_level
            },

            "threat": {
                "threat": threat,
                "confidence": confidence
            },

            "decision": {
                "action": action,
                "severity": risk_level,
                "message": security["message"]
            },

            "ai": ai_result,

            "incident": incident,

            "scan": scan
        }

    def analyze_file(self, file_path):

        result = (
            self.file_guardian
            .analyze(file_path)
        )

        tool_evidence = (
            self.security_tool_adapter
            .collect_file_evidence(file_path)
        )

        # =========================================
        # EVIDENCE
        # =========================================

        evidence = [
            {
                "source": "FileGuardian",
                "category": "file_analysis",
                "target": file_path,
                "severity": result.get(
                    "severity",
                    "LOW"
                ),
                "data": result
            },
            {
                "source": "SecurityToolAdapter",
                "category": "tool_evidence",
                "target": file_path,
                "severity": "INFO",
                "data": tool_evidence
            }
        ]

        evidence_security = (
            self.evidence_analyzer
            .analyze(evidence)
        )

        # =========================================
        # STRUCTURED RISK SIGNALS
        # =========================================

        signals = {

            "executable_file":
                result.get(
                    "executable_file",
                    False
                ),

            "double_extension":
                result.get(
                    "double_extension",
                    False
                ),

            "large_file":
                result.get(
                    "large_file",
                    False
                ),

            "hidden_file":
                result.get(
                    "hidden_file",
                    False
                ),

            # =====================================
            # ADVANCED FILE INTELLIGENCE
            # =====================================

            "suspicious_filename":
                result.get(
                    "suspicious_filename",
                    False
                ),

            "archive_file":
                result.get(
                    "archive_file",
                    False
                ),

            "system_file":
                result.get(
                    "system_file",
                    False
                )
        }

        # =========================================
        # RISK ENGINE
        # =========================================

        risk_result = (
            self.risk_engine
            .calculate_risk(signals)
        )

        # =========================================
        # THREAT CLASSIFICATION
        # =========================================

        classification = (
            self.threat_classifier
            .classify(signals)
        )

        # =========================================
        # DECISION ENGINE
        # =========================================

        decision = (
            self.decision_engine
            .decide(
                risk_result["risk_score"]
            )
        )

        # =========================================
        # CONSISTENT FILE SECURITY RESULT
        # =========================================

        security = {
            "signals": signals,
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "threat": classification["threat"],
            "confidence": classification["confidence"],
            "action": decision["action"],
            "severity": decision["severity"],
            "message": decision["message"],
            "evidence_analysis": evidence_security
        }

        # =========================================
        # AI ANALYSIS
        # =========================================

        ai_result = (
            self.ai_orchestrator
            .analyze_file(
                file_path=file_path,
                file_analysis=result,
                security=security,
                risk_result=risk_result,
                classification=classification,
                decision=decision
            )
        )

        # =========================================
        # CREATE INCIDENT
        # =========================================

        incident = (
            self.incident_manager
            .create_incident(
                incident_type="FILE",
                target=file_path,
                risk_score=
                    risk_result["risk_score"],
                risk_level=
                    risk_result["risk_level"],
                threat=
                    classification["threat"],
                action=
                    decision["action"],
                evidence=evidence,
                description=
                    decision["message"]
            )
        )

        # =========================================
        # CREATE SCAN RECORD
        # =========================================

        self.scan_id += 1

        ai_data = ai_result or {}

        file_scan_record = {

            "id": self.scan_id,

            "timestamp":
                datetime.now().isoformat(),

            "type": "FILE",

            "target": file_path,

            "risk_score":
                risk_result["risk_score"],

            "risk_level":
                risk_result["risk_level"],

            "threat":
                classification["threat"],

            "action":
                decision["action"],

            "ai_model":
                ai_data.get(
                    "model",
                    "VAJRA AI"
                ),

            "ai_runtime":
                ai_data.get(
                    "runtime",
                    "development"
                ),

            "ai_status":
                ai_data.get(
                    "status",
                    "ready"
                ),

            "ai_backend":
                ai_data.get(
                    "backend",
                    "development"
                ),

            "ai_backend_status":
                ai_data.get(
                    "backend_status",
                    "unknown"
                ),

            "sha256":
                result.get("sha256")
        }

        # =========================================
        # SAVE SCAN
        # =========================================

        self.storage.save_scan(file_scan_record)

        self.scan_history = self.storage.get_scans(
            limit=50
        )

        # =========================================
        # FINAL RESPONSE
        # =========================================

        return {

            "type": "file",

            "target": file_path,

            "file_analysis": result,

            "signals": signals,

            "risk": risk_result,

            "threat": classification,

            "decision": decision,

            "security": security,

            "ai": ai_result,

            "scan": file_scan_record,

            "incident": incident
        }

    # =========================================
    # PRIVACY ANALYSIS
    # =========================================

    def analyze_privacy(self):

        result = (
            self.privacy_analyzer
            .analyze()
            or {}
        )

        # =========================================
        # PRIVACY RISK
        # =========================================

        risk_level = str(
            result.get(
                "risk_level",
                "LOW"
            )
        ).upper()

        if risk_level == "CRITICAL":

            risk_score = 90

        elif risk_level == "HIGH":

            risk_score = 65

        elif risk_level == "MEDIUM":

            risk_score = 35

        else:

            risk_score = 10

        # =========================================
        # THREAT CLASSIFICATION
        # =========================================

        if risk_level in [
            "HIGH",
            "CRITICAL"
        ]:

            threat = "SUSPICIOUS"

        elif risk_level == "MEDIUM":

            threat = "REVIEW"

        else:

            threat = "LOW RISK"

        # =========================================
        # DECISION ENGINE
        # =========================================

        decision = (
            self.decision_engine
            .decide(risk_score)
        )

        # =========================================
        # AI ANALYSIS
        # =========================================

        ai_result = (
            self.ai_orchestrator
            .inference_manager
            .run(
                input_type="text",
                data={
                    "privacy_analysis":
                        result
                }
            )
            or {}
        )

        # =========================================
        # EVIDENCE
        # =========================================

        evidence = [{
            "source": "PrivacyAnalyzer",
            "category": "privacy_analysis",
            "target": "Local System",
            "severity": risk_level,
            "data": result
        }]

        # =========================================
        # CREATE INCIDENT
        # =========================================

        incident = (
            self.incident_manager
            .create_incident(
                incident_type="PRIVACY",
                target="Local System",
                risk_score=risk_score,
                risk_level=risk_level,
                threat=threat,
                action=decision["action"],
                evidence=evidence,
                description=decision["message"]
            )
        )

        # =========================================
        # CREATE SCAN RECORD
        # =========================================

        self.scan_id += 1

        scan_record = {

            "id": self.scan_id,

            "timestamp":
                datetime.now().isoformat(),

            "type": "PRIVACY",

            "target": "Local System",

            "risk_score": risk_score,

            "risk_level": risk_level,

            "threat": threat,

            "action": decision["action"],

            "ai_model":
                ai_result.get(
                    "model",
                    "VAJRA AI"
                ),

            "ai_runtime":
                ai_result.get(
                    "runtime",
                    "development"
                ),

            "ai_status":
                ai_result.get(
                    "status",
                    "ready"
                ),

            "ai_backend":
                ai_result.get(
                    "backend",
                    "development"
                ),

            "ai_backend_status":
                ai_result.get(
                    "backend_status",
                    "unknown"
                )
        }

        # =========================================
        # SAVE SCAN
        # =========================================

        self.storage.save_scan(scan_record)

        self.scan_history = self.storage.get_scans(
            limit=50
        )

        # =========================================
        # FINAL RESPONSE
        # =========================================

        return {

            "type": "privacy",

            "security": result,

            "risk": {
                "risk_score":
                    risk_score,

                "risk_level":
                    risk_level
            },

            "threat": {
                "threat":
                    threat
            },

            "decision":
                decision,

            "ai":
                ai_result,

            "scan":
                scan_record,

            "incident":
                incident
        }

    # =========================================
    # GET SCAN HISTORY
    # =========================================

    def get_scan_history(
        self,
        limit=20
    ):

        try:

            limit = int(limit)

        except (
            TypeError,
            ValueError
        ):

            limit = 20

        limit = max(
            1,
            min(
                limit,
                50
            )
        )

        return {

            "count":
                len(self.scan_history),

            "scans":
                self.scan_history[:limit]
        }

    # =========================================
    # SECURITY ANALYTICS
    # =========================================

    def get_security_analytics(self):

        scans = self.scan_history

        if not scans:

            return {

                "total_scans": 0,

                "average_risk": 0,

                "highest_risk": 0,

                "low_risk": 0,

                "medium_risk": 0,

                "high_risk": 0,

                "critical_risk": 0,

                "timeline": []
            }

        risk_scores = [

            int(
                scan.get(
                    "risk_score",
                    0
                )
            )

            for scan in scans
        ]

        low = 0
        medium = 0
        high = 0
        critical = 0

        for scan in scans:

            level = str(
                scan.get(
                    "risk_level",
                    "LOW"
                )
            ).upper()

            if level == "CRITICAL":

                critical += 1

            elif level == "HIGH":

                high += 1

            elif level == "MEDIUM":

                medium += 1

            else:

                low += 1

        timeline = []

        for scan in reversed(
            scans
        ):

            timeline.append({

                "id":
                    scan.get("id"),

                "timestamp":
                    scan.get(
                        "timestamp"
                    ),

                "risk_score":
                    scan.get(
                        "risk_score",
                        0
                    ),

                "risk_level":
                    scan.get(
                        "risk_level",
                        "LOW"
                    ),

                "target":
                    scan.get(
                        "target",
                        ""
                    ),

                "action":
                    scan.get(
                        "action",
                        "ALLOW"
                    )
            })

        return {

            "total_scans":
                len(scans),

            "average_risk":
                round(
                    sum(risk_scores)
                    / len(risk_scores),
                    2
                ),

            "highest_risk":
                max(risk_scores),

            "low_risk":
                low,

            "medium_risk":
                medium,

            "high_risk":
                high,

            "critical_risk":
                critical,

            "timeline":
                timeline
        }

    # =========================================
    # CLEAR SCAN HISTORY
    # =========================================

    def clear_scan_history(self):

        self.scan_history.clear()

        self.storage.clear_scans()

        self.scan_id = 0

        return {

            "status":
                "cleared",

            "count":
                0
        }

    # =========================================
    # AI BACKEND STATUS
    # =========================================

    def get_ai_backend_status(self):

        return (
            self.ai_orchestrator
            .get_backend_status()
        )