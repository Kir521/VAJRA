class ThreatClassifier:

    def classify(self, signals):

        score = 0

        # =========================================
        # URL SECURITY SIGNALS
        # =========================================

        if signals.get("malicious_url"):
            score += 40

        if signals.get("suspicious_domain"):
            score += 20

        if signals.get("credential_request"):
            score += 20

        if signals.get("suspicious_redirect"):
            score += 10

        if signals.get("known_threat"):
            score += 30

        # =========================================
        # URL EVIDENCE SIGNALS
        # =========================================

        if signals.get("ip_address_url"):
            score += 15

        if signals.get("suspicious_tld"):
            score += 10

        if signals.get("encoded_url"):
            score += 5

        # =========================================
        # ADVANCED URL INTELLIGENCE
        # =========================================

        if signals.get("punycode_domain"):
            score += 15

        if signals.get("username_in_url"):
            score += 10

        if signals.get("unusual_port"):
            score += 10

        # =========================================
        # SUBDOMAIN ANALYSIS
        # =========================================

        if signals.get("many_subdomains"):
            score += 10

        if signals.get("url_too_long"):
            score += 5

        # =========================================
        # FILE SECURITY SIGNALS
        # =========================================

        if signals.get("executable_file"):
            score += 20

        if signals.get("double_extension"):
            score += 30

        if signals.get("large_file"):
            score += 5

        if signals.get("hidden_file"):
            score += 10

        # =========================================
        # ADVANCED FILE INTELLIGENCE
        # =========================================

        if signals.get("suspicious_filename"):
            score += 10

        if signals.get("system_file"):
            score += 5

        # =========================================
        # LIMIT SCORE
        # =========================================

        score = min(score, 100)

        # =========================================
        # THREAT CLASSIFICATION
        # =========================================

        if score >= 70:
            threat = "HIGH RISK"

        elif score >= 40:
            threat = "SUSPICIOUS"

        else:
            threat = "LOW RISK"

        # =========================================
        # FINAL RESULT
        # =========================================

        return {
            "threat": threat,
            "confidence": min(score + 10, 99)
        }