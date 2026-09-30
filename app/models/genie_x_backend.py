import os
import platform
import shutil
import subprocess


class GenieXBackend:

    def __init__(self):
        self.provider = "Qualcomm GenieX"
        self.runtime = "GenieX"
        self.model = "unsloth/Qwen3.5-2B-GGUF"

        self.available = False
        self.last_error = None
        self.executable = None

        self.machine = platform.machine()
        self.system = platform.system()

    def find_runtime(self):

        # First check PATH
        path_executable = shutil.which("geniex")

        if path_executable:
            return path_executable

        # Optional local runtime location
        local_paths = [
            os.path.join(
                os.getcwd(),
                "runtime",
                "geniex",
                "geniex.exe"
            ),
            os.path.join(
                os.getcwd(),
                "runtime",
                "geniex",
                "geniex-cli.exe"
            ),
        ]

        for path in local_paths:
            if os.path.exists(path):
                return path

        return None

    def check_runtime(self):

        executable = self.find_runtime()

        if executable is None:

            self.available = False
            self.executable = None
            self.last_error = "GenieX CLI not found."

            return {
                "status": "not_available",
                "provider": self.provider,
                "runtime": self.runtime,
                "model": self.model,
                "error": self.last_error
            }

        self.executable = executable

        try:

            result = subprocess.run(
                [executable, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )

            self.available = result.returncode == 0

            return {
                "status": (
                    "available"
                    if self.available
                    else "not_available"
                ),
                "provider": self.provider,
                "runtime": self.runtime,
                "model": self.model,
                "executable": executable,
                "output": result.stdout[:1000],
                "error": result.stderr[:1000]
            }
        except Exception as error:

            self.available = False
            self.last_error = str(error)

            if self.machine.upper() == "AMD64" and "WinError 216" in str(error):

                return {
                    "status": "incompatible_platform",
                    "provider": self.provider,
                    "runtime": self.runtime,
                    "model": self.model,
                    "executable": executable,
                    "system": self.system,
                    "machine": self.machine,
                    "error": self.last_error,
                    "message": (
                        "GenieX was detected, but this machine is "
                        "AMD64. A compatible Snapdragon Windows "
                        "ARM64 environment is required for local "
                        "GenieX execution."
                    )
                }

            return {
                "status": "error",
                "provider": self.provider,
                "runtime": self.runtime,
                "model": self.model,
                "executable": executable,
                "system": self.system,
                "machine": self.machine,
                "error": self.last_error
            }
    def get_status(self):

        return {
            "provider": self.provider,
            "runtime": self.runtime,
            "model": self.model,
            "available": self.available,
            "executable": self.executable,
            "system": self.system,
            "machine": self.machine,
            "error": self.last_error
        }

    def analyze(self, prompt):

        runtime_status = self.check_runtime()

        if runtime_status["status"] != "available":

            return {
                "status": "runtime_not_available",
                "provider": self.provider,
                "runtime": self.runtime,
                "model": self.model,
                "message": (
                    "GenieX runtime is not available on "
                    "this development machine."
                ),
                "runtime_check": runtime_status
            }

        return {
            "status": "inference_ready",
            "provider": self.provider,
            "runtime": self.runtime,
            "model": self.model,
            "executable": self.executable,
            "message": (
                "GenieX runtime is available. "
                "Actual Qwen3.5-2B inference can be "
                "executed on the compatible Snapdragon "
                "Windows environment."
            ),
            "prompt": prompt
        }