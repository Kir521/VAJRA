import hashlib
import os


class FileGuardian:

    def analyze(self, file_path):

        result = {
            "file": file_path,
            "exists": False,
            "size_bytes": 0,
            "extension": "",
            "sha256": None,
            "signals": [],

            # Structured security signals
            "executable_file": False,
            "double_extension": False,
            "large_file": False,
            "hidden_file": False,

            # Advanced file intelligence
            "suspicious_filename": False,
            "archive_file": False,
            "system_file": False,

            "severity": "LOW"
        }

        # =========================================
        # FILE EXISTENCE
        # =========================================

        if not os.path.isfile(file_path):

            result["signals"].append(
                "File does not exist"
            )

            return result

        result["exists"] = True

        # =========================================
        # FILE INFORMATION
        # =========================================

        result["size_bytes"] = os.path.getsize(file_path)

        result["extension"] = (
            os.path.splitext(file_path)[1].lower()
        )

        # =========================================
        # SHA-256 HASH
        # =========================================

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:

            for chunk in iter(
                lambda: file.read(8192),
                b""
            ):

                sha256.update(chunk)

        result["sha256"] = sha256.hexdigest()

        # =========================================
        # SUSPICIOUS EXTENSIONS
        # =========================================

        suspicious_extensions = {
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
            ".msi",
            ".dll",
            ".hta"
        }

        if result["extension"] in suspicious_extensions:

            result["signals"].append(
                "Potentially executable or script file type"
            )

            result["executable_file"] = True
            result["severity"] = "MEDIUM"

        # =========================================
        # DOUBLE EXTENSION
        # =========================================

        filename = os.path.basename(file_path).lower()

        suspicious_patterns = [
            ".pdf.exe",
            ".doc.exe",
            ".docx.exe",
            ".xls.exe",
            ".xlsx.exe",
            ".jpg.exe",
            ".png.exe",
            ".txt.exe",
            ".pdf.scr",
            ".doc.scr",
            ".jpg.scr"
        ]

        for pattern in suspicious_patterns:

            if filename.endswith(pattern):

                result["signals"].append(
                    "Suspicious double file extension detected"
                )

                result["double_extension"] = True
                result["severity"] = "HIGH"

                break

        # =========================================
        # SUSPICIOUS FILENAME
        # =========================================

        suspicious_filename_patterns = [
            "invoice",
            "payment",
            "refund",
            "password",
            "verify",
            "verification",
            "account",
            "security",
            "update",
            "document",
            "urgent",
            "important"
        ]

        filename_without_extension = os.path.splitext(
            filename
        )[0]

        for pattern in suspicious_filename_patterns:

            if pattern in filename_without_extension:

                result["signals"].append(
                    "Suspicious filename pattern detected"
                )

                result["suspicious_filename"] = True

                break

        # =========================================
        # ARCHIVE FILE
        # =========================================

        archive_extensions = {
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            ".bz2"
        }

        if result["extension"] in archive_extensions:

            result["archive_file"] = True

            result["signals"].append(
                "Archive file detected"
            )

        # =========================================
        # SYSTEM FILE
        # =========================================

        system_extensions = {
            ".sys",
            ".dll",
            ".drv",
            ".ocx"
        }

        if result["extension"] in system_extensions:

            result["system_file"] = True

            result["signals"].append(
                "System-related file detected"
            )

        # =========================================
        # LARGE FILE
        # =========================================

        if result["size_bytes"] > 100 * 1024 * 1024:

            result["signals"].append(
                "Large file detected"
            )

            result["large_file"] = True

        # =========================================
        # EMPTY FILE
        # =========================================

        if result["size_bytes"] == 0:

            result["signals"].append(
                "Empty file detected"
            )

        # =========================================
        # HIDDEN FILE
        # =========================================

        try:

            if os.name == "nt":

                import ctypes

                attributes = ctypes.windll.kernel32.GetFileAttributesW(
                    file_path
                )

                if attributes != -1 and attributes & 0x2:

                    result["signals"].append(
                        "Hidden file attribute detected"
                    )

                    result["hidden_file"] = True

        except Exception:

            # Hidden-file detection is optional.
            pass

        # =========================================
        # FINAL SEVERITY
        # =========================================

        if result["double_extension"]:

            result["severity"] = "HIGH"

        elif result["executable_file"]:

            result["severity"] = "MEDIUM"

        return result