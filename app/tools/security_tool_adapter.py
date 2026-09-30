import hashlib
import shutil
import subprocess
import socket
from urllib.parse import urlparse
from pathlib import Path


class SecurityToolAdapter:

    # =========================================
    # URL EVIDENCE
    # =========================================

    def collect_url_evidence(self, url):

        evidence = []

        try:

            parsed = urlparse(url)
            domain = parsed.hostname

            if not domain:

                return {
                    "status": "failed",
                    "target": url,
                    "error": "Invalid URL"
                }

            # =========================================
            # URL PARSER
            # =========================================

            evidence.append({
                "status": "success",
                "tool": "URLParser",
                "target": url,
                "scheme": parsed.scheme,
                "domain": domain,
                "port": parsed.port
            })

            # =========================================
            # DNS
            # =========================================

            try:

                ip_address = socket.gethostbyname(domain)

                evidence.append({
                    "status": "success",
                    "tool": "DNS",
                    "target": domain,
                    "ip_address": ip_address,
                    "dns_resolution_failed": False
                })

                # =========================================
                # REVERSE DNS
                # =========================================

                try:

                    reverse_name = socket.gethostbyaddr(
                        ip_address
                    )[0]

                    evidence.append({
                        "status": "success",
                        "tool": "ReverseDNS",
                        "target": ip_address,
                        "hostname": reverse_name
                    })

                except Exception as error:

                    evidence.append({
                        "status": "failed",
                        "tool": "ReverseDNS",
                        "target": ip_address,
                        "error": str(error)
                    })

            except Exception as error:

                evidence.append({
                    "status": "failed",
                    "tool": "DNS",
                    "target": domain,
                    "error": str(error),
                    "dns_resolution_failed": True
                })

            # =========================================
            # FINAL URL EVIDENCE
            # =========================================

            return {
                "status": "success",
                "target": url,
                "evidence": evidence
            }

        except Exception as error:

            return {
                "status": "failed",
                "target": url,
                "error": str(error)
            }

    # =========================================
    # TOOL AVAILABILITY
    # =========================================

    def is_available(self, tool):

        return shutil.which(tool) is not None

    # =========================================
    # TOOL VERSION
    # =========================================

    def get_version(self, tool):

        if not self.is_available(tool):

            return {
                "tool": tool,
                "available": False,
                "version": None
            }

        try:

            result = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout.strip()

            if not output:

                output = result.stderr.strip()

            return {
                "tool": tool,
                "available": True,
                "version": output.split("\n")[0]
            }

        except Exception as error:

            return {
                "tool": tool,
                "available": True,
                "version": None,
                "error": str(error)
            }

    # =========================================
    # TOOL STATUS
    # =========================================

    def get_tool_status(self):

        tools = [
            "nmap",
            "yara",
            "clamscan",
            "tshark",
            "curl"
        ]

        results = []

        for tool in tools:

            results.append(
                self.get_version(tool)
            )

        return results

    # =========================================
    # FILE HASH
    # =========================================

    def hash_file(self, file_path):

        path = Path(file_path)

        if not path.exists():

            return {
                "status": "error",
                "message": "File does not exist."
            }

        sha256 = hashlib.sha256()

        try:

            with path.open("rb") as file:

                for chunk in iter(
                    lambda: file.read(1024 * 1024),
                    b""
                ):

                    sha256.update(chunk)

            return {
                "status": "success",
                "tool": "SHA-256",
                "target": str(path),
                "sha256": sha256.hexdigest()
            }

        except Exception as error:

            return {
                "status": "error",
                "tool": "SHA-256",
                "target": str(path),
                "error": str(error)
            }

    # =========================================
    # FILE EVIDENCE
    # =========================================

    def collect_file_evidence(self, file_path):

        evidence = []

        hash_result = self.hash_file(
            file_path
        )

        evidence.append(hash_result)

        return {
            "status": "success",
            "target": str(file_path),
            "evidence": evidence
        }