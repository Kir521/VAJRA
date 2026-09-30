import os
import platform
import subprocess


class PrivacyAnalyzer:

    def analyze(self):

        signals = {
            "sensitive_files": False,
            "excessive_permissions": False,
            "suspicious_process": False,
            "privacy_risk": False
        }

        findings = []

        # -------------------------------------------------
        # 1. Sensitive user directories
        # -------------------------------------------------

        sensitive_paths = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads")
        ]

        existing_paths = [
            path for path in sensitive_paths
            if os.path.exists(path)
        ]

        if existing_paths:

            signals["sensitive_files"] = True

            findings.append(
                "User data directories are accessible."
            )

        # -------------------------------------------------
        # 2. Permission check
        # -------------------------------------------------

        permission_risk = False

        if platform.system() != "Windows":

            for path in existing_paths:

                try:

                    mode = os.stat(path).st_mode

                    if mode & 0o004:
                        permission_risk = True
                        break

                except OSError:
                    continue

        if permission_risk:

            signals["excessive_permissions"] = True

            findings.append(
                "A sensitive user directory has broad read permissions."
            )

        # -------------------------------------------------
        # 3. Conservative suspicious-process check
        # -------------------------------------------------

        suspicious_names = {
            "keylogger",
            "screenlogger",
            "spyware",
            "infostealer"
        }

        try:

            if platform.system() == "Windows":

                result = subprocess.run(
                    [
                        "tasklist",
                        "/FO",
                        "CSV",
                        "/NH"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                process_output = result.stdout.lower()

                for name in suspicious_names:

                    if name in process_output:

                        signals["suspicious_process"] = True

                        findings.append(
                            "A process with a privacy-sensitive name was detected."
                        )

                        break

        except Exception:
            pass

        # -------------------------------------------------
        # 4. Aggregate privacy risk
        # -------------------------------------------------

        if (
            signals["excessive_permissions"]
            or signals["suspicious_process"]
        ):

            signals["privacy_risk"] = True

        elif signals["sensitive_files"]:

            signals["privacy_risk"] = True

        # -------------------------------------------------
        # 5. Calculate risk level
        # -------------------------------------------------

        risk_level = self._calculate_level(
            signals
        )

        return {
            "signals": signals,
            "findings": findings,
            "risk_level": risk_level
        }

    def _calculate_level(self, signals):

        score = 0

        if signals.get("sensitive_files"):
            score += 1

        if signals.get("excessive_permissions"):
            score += 2

        if signals.get("suspicious_process"):
            score += 2

        if signals.get("privacy_risk"):
            score += 1

        if score >= 5:
            return "HIGH"

        if score >= 2:
            return "MEDIUM"

        return "LOW"
