class DecisionEngine:

    def decide(self, risk_score):

        if risk_score >= 80:
            return {
                "action": "BLOCK",
                "severity": "CRITICAL",
                "message": "VAJRA recommends blocking this activity."
            }

        elif risk_score >= 60:
            return {
                "action": "WARN",
                "severity": "HIGH",
                "message": "VAJRA detected significant security risk."
            }

        elif risk_score >= 30:
            return {
                "action": "REVIEW",
                "severity": "MEDIUM",
                "message": "VAJRA recommends reviewing this activity."
            }

        else:
            return {
                "action": "ALLOW",
                "severity": "LOW",
                "message": "No significant risk detected."
            }