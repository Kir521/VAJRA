class RiskEngine:

    def calculate_risk(self, signals):

        score = 0
        reasons = []

        # =========================================
        # URL SECURITY SIGNALS
        # =========================================

        if signals.get("malicious_url"):
            score += 40
            reasons.append("Malicious URL indicator detected")

        if signals.get("suspicious_domain"):
            score += 20
            reasons.append(
                "Suspicious domain or insecure scheme detected"
            )

        if signals.get("credential_request"):
            score += 20
            reasons.append(
                "Credential-related request detected"
            )

        if signals.get("suspicious_redirect"):
            score += 10
            reasons.append(
                "Suspicious redirect indicator detected"
            )

        if signals.get("known_threat"):
            score += 30
            reasons.append(
                "Known threat indicator detected"
            )

        # =========================================
        # URL EVIDENCE SIGNALS
        # =========================================

        if signals.get("ip_address_url"):
            score += 15
            reasons.append(
                "URL uses an IP address instead of a domain"
            )

        if signals.get("suspicious_tld"):
            score += 10
            reasons.append(
                "Suspicious top-level domain detected"
            )

        if signals.get("encoded_url"):
            score += 5
            reasons.append(
                "Encoded URL content detected"
            )

        # =========================================
        # ADVANCED URL INTELLIGENCE
        # =========================================

        if signals.get("punycode_domain"):
            score += 15
            reasons.append(
                "Punycode domain detected"
            )

        if signals.get("username_in_url"):
            score += 10
            reasons.append(
                "Username embedded in URL detected"
            )

        if signals.get("unusual_port"):
            score += 10
            reasons.append(
                "Unusual URL port detected"
            )

        # =========================================
        # SUBDOMAIN ANALYSIS
        # =========================================

        if signals.get("many_subdomains"):
            score += 10
            reasons.append(
                "Unusually deep subdomain structure detected"
            )

        # =========================================
        # URL LENGTH
        # =========================================

        if signals.get("url_too_long"):
            score += 5
            reasons.append(
                "URL is unusually long"
            )

        # =========================================
        # FILE SECURITY SIGNALS
        # =========================================

        if signals.get("executable_file"):
            score += 20
            reasons.append(
                "Potentially executable or script file detected"
            )

        if signals.get("double_extension"):
            score += 30
            reasons.append(
                "Suspicious double file extension detected"
            )

        if signals.get("large_file"):
            score += 5
            reasons.append(
                "Large file detected"
            )

        if signals.get("hidden_file"):
            score += 10
            reasons.append(
                "Hidden file detected"
            )

        # =========================================
        # ADVANCED FILE INTELLIGENCE
        # =========================================

        if signals.get("suspicious_filename"):
            score += 10
            reasons.append(
                "Suspicious filename pattern detected"
            )

        if signals.get("system_file"):
            score += 5
            reasons.append(
                "System-related file detected"
            )

        # =========================================
        # LIMIT SCORE
        # =========================================

        score = min(score, 100)

        # =========================================
        # RISK LEVEL
        # =========================================

        if score >= 70:
            level = "CRITICAL"

        elif score >= 50:
            level = "HIGH"

        elif score >= 25:
            level = "MEDIUM"

        else:
            level = "LOW"

        # =========================================
        # FINAL RESULT
        # =========================================

        return {
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons
        }