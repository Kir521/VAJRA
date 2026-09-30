import re
from urllib.parse import urlparse


class EmailMessageGuardian:

    URGENCY_WORDS = {
        "urgent",
        "immediately",
        "immediate",
        "act now",
        "action required",
        "within 24 hours",
        "verify now",
        "last warning",
        "final warning",
        "account suspended",
        "account will be closed",
    }

    CREDENTIAL_WORDS = {
        "password",
        "passcode",
        "otp",
        "one time password",
        "verification code",
        "login",
        "username",
        "credentials",
        "bank account",
        "card number",
        "cvv",
        "pin",
    }

    FINANCIAL_WORDS = {
        "payment",
        "refund",
        "invoice",
        "bank",
        "credit card",
        "debit card",
        "transfer",
        "transaction",
        "upi",
        "prize",
        "reward",
        "lottery",
    }

    SUSPICIOUS_ATTACHMENT_WORDS = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".ps1",
        ".msi",
        ".jar",
    }

    def analyze(self, message, subject=""):
        message = str(message or "")
        subject = str(subject or "")

        text = f"{subject} {message}".lower()

        findings = []
        signals = {
            "urgency_language": False,
            "credential_request": False,
            "financial_request": False,
            "suspicious_link": False,
            "multiple_links": False,
            "suspicious_attachment": False,
            "impersonation_indicator": False,
            "social_engineering": False,
            "known_threat": False,
        }

        # 1. Urgency / pressure
        urgency_hits = [
            word for word in self.URGENCY_WORDS
            if word in text
        ]

        if urgency_hits:
            signals["urgency_language"] = True
            findings.append(
                "Urgency or pressure language detected."
            )

        # 2. Credential request
        credential_hits = [
            word for word in self.CREDENTIAL_WORDS
            if word in text
        ]

        credential_context = any(
            phrase in text
            for phrase in [
                "enter your password",
                "enter password",
                "verify your account",
                "verify your identity",
                "confirm your login",
                "provide your otp",
                "share your otp",
                "send your otp",
                "login immediately",
            ]
        )

        if credential_hits and credential_context:
            signals["credential_request"] = True
            findings.append(
                "Message appears to request account or authentication information."
            )

        # 3. Financial request
        financial_hits = [
            word for word in self.FINANCIAL_WORDS
            if word in text
        ]

        financial_context = any(
            phrase in text
            for phrase in [
                "send money",
                "make payment",
                "pay immediately",
                "bank details",
                "card details",
                "upi payment",
                "transfer money",
                "claim your reward",
                "claim your prize",
            ]
        )

        if financial_hits and financial_context:
            signals["financial_request"] = True
            findings.append(
                "Message contains a financial or payment-related request."
            )

        # 4. URLs
        urls = re.findall(
            r"https?://[^\s<>'\"]+",
            message,
            flags=re.IGNORECASE
        )

        if len(urls) > 1:
            signals["multiple_links"] = True
            findings.append(
                "Multiple links detected in the message."
            )

        for url in urls:
            clean_url = url.rstrip(".,);]}>")
            try:
                parsed = urlparse(clean_url)
                domain = parsed.hostname or ""

                if (
                    parsed.username
                    or parsed.port not in (None, 80, 443)
                    or domain.startswith("xn--")
                    or ".xn--" in domain
                ):
                    signals["suspicious_link"] = True
                    findings.append(
                        "A link contains suspicious URL characteristics."
                    )
                    break

                if parsed.scheme == "http":
                    signals["suspicious_link"] = True
                    findings.append(
                        "An insecure HTTP link was detected."
                    )
                    break

            except Exception:
                signals["suspicious_link"] = True
                findings.append(
                    "A malformed or suspicious link was detected."
                )
                break

        # 5. Attachment indicators
        attachment_hits = [
            ext for ext in self.SUSPICIOUS_ATTACHMENT_WORDS
            if ext in text
        ]

        if attachment_hits:
            signals["suspicious_attachment"] = True
            findings.append(
                "Potentially executable attachment indicator detected."
            )

        # 6. Impersonation indicators
        impersonation_phrases = [
            "security team",
            "support team",
            "administrator",
            "admin team",
            "it department",
            "bank support",
            "account security",
            "customer support",
            "official support",
            "verify your account",
        ]

        if any(phrase in text for phrase in impersonation_phrases):
            signals["impersonation_indicator"] = True
            findings.append(
                "Possible trusted-organization impersonation indicator detected."
            )

        # 7. Social engineering combination
        if (
            signals["urgency_language"]
            and (
                signals["credential_request"]
                or signals["financial_request"]
            )
        ):
            signals["social_engineering"] = True
            findings.append(
                "Urgency combined with a credential or financial request."
            )

        # Risk calculation
        score = 0

        if signals["urgency_language"]:
            score += 15

        if signals["credential_request"]:
            score += 25

        if signals["financial_request"]:
            score += 25

        if signals["suspicious_link"]:
            score += 20

        if signals["multiple_links"]:
            score += 5

        if signals["suspicious_attachment"]:
            score += 25

        if signals["impersonation_indicator"]:
            score += 15

        if signals["social_engineering"]:
            score += 20

        score = min(score, 100)

        if score >= 70:
            risk_level = "CRITICAL"
            threat = "HIGH RISK"
            action = "BLOCK"
        elif score >= 50:
            risk_level = "HIGH"
            threat = "SUSPICIOUS"
            action = "WARN"
        elif score >= 25:
            risk_level = "MEDIUM"
            threat = "SUSPICIOUS"
            action = "REVIEW"
        else:
            risk_level = "LOW"
            threat = "LOW RISK"
            action = "ALLOW"

        confidence = min(
            max(score + 15, 20),
            99
        )

        return {
            "type": "EMAIL_MESSAGE",
            "risk_score": score,
            "risk_level": risk_level,
            "threat": threat,
            "action": action,
            "confidence": confidence,
            "signals": signals,
            "findings": findings,
            "url_count": len(urls),
            "subject": subject,
        }
