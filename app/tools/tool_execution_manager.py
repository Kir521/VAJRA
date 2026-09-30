import shutil
import subprocess


class ToolExecutionManager:

    ALLOWED_TOOLS = {
        "nmap": "nmap",
        "yara": "yara",
        "clamscan": "clamscan",
        "tshark": "tshark",
        "curl": "curl"
    }

    def is_allowed(self, tool):
        return tool in self.ALLOWED_TOOLS

    def is_installed(self, tool):
        command = self.ALLOWED_TOOLS.get(tool)

        if not command:
            return False

        return shutil.which(command) is not None

    def run_version_check(self, tool):

        if not self.is_allowed(tool):
            return {
                "success": False,
                "error": "Tool is not allowed"
            }

        if not self.is_installed(tool):
            return {
                "success": False,
                "error": f"{tool} is not installed"
            }

        try:
            result = subprocess.run(
                [self.ALLOWED_TOOLS[tool], "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout.strip()

            if not output:
                output = result.stderr.strip()

            return {
                "success": True,
                "tool": tool,
                "output": output
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Tool execution timed out"
            }

        except Exception as error:
            return {
                "success": False,
                "error": str(error)
            }