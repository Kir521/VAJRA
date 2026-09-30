from urllib.parse import urlparse
import ipaddress


class URLGuardian:

    def analyze(self, url):

        signals = {
            "malicious_url": False,
            "suspicious_domain": False,
            "credential_request": False,
            "suspicious_redirect": False,
            "known_threat": False,

            # Evidence signals
            "ip_address_url": False,
            "suspicious_tld": False,
            "encoded_url": False,
            "many_subdomains": False,
            "url_too_long": False,

            # Advanced URL intelligence
            "punycode_domain": False,
            "username_in_url": False,
            "unusual_port": False
        }

        parsed = urlparse(url)

        domain = parsed.hostname.lower() if parsed.hostname else ""
        path = parsed.path.lower()
        query = parsed.query.lower()

        # =========================================
        # SCHEME
        # =========================================

        if parsed.scheme != "https":
            signals["suspicious_domain"] = True

        # =========================================
        # IP ADDRESS
        # =========================================

        try:
            ipaddress.ip_address(domain)

            signals["ip_address_url"] = True
            signals["suspicious_domain"] = True

        except ValueError:
            pass

        # =========================================
        # CREDENTIAL / PHISHING WORDS
        # =========================================

        suspicious_words = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "bank",
            "update"
        ]

        for word in suspicious_words:

            if word in path or word in query:

                signals["credential_request"] = True
                break

        # =========================================
        # URL LENGTH
        # =========================================

        if len(url) > 150:

            signals["suspicious_redirect"] = True
            signals["url_too_long"] = True

        # =========================================
        # ENCODED / OBFUSCATED URL
        # =========================================

        if "%" in url:

            signals["encoded_url"] = True

        # =========================================
        # MANY SUBDOMAINS
        # =========================================

        if domain and not signals["ip_address_url"]:

            domain_parts = domain.split(".")

            if len(domain_parts) >= 4:

                signals["many_subdomains"] = True

        # =========================================
        # SUSPICIOUS TLD
        # =========================================

        suspicious_tlds = {
            ".zip",
            ".mov",
            ".click",
            ".top",
            ".xyz"
        }

        for tld in suspicious_tlds:

            if domain.endswith(tld):

                signals["suspicious_tld"] = True
                break

        # =========================================
        # PUNYCODE DOMAIN
        # =========================================

        if domain.startswith("xn--") or ".xn--" in domain:

            signals["punycode_domain"] = True

        # =========================================
        # USERNAME IN URL
        # =========================================

        if parsed.username:

            signals["username_in_url"] = True

        # =========================================
        # UNUSUAL PORT
        # =========================================

        if parsed.port is not None:

            if parsed.port not in {80, 443}:

                signals["unusual_port"] = True

        return signals