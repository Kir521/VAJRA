from app.security.file_guardian import FileGuardian
from app.tools.tool_execution_manager import ToolExecutionManager
from app.tools.evidence_collector import EvidenceCollector


class FileSecurityPipeline:

    def __init__(self):

        self.file_guardian = FileGuardian()
        self.tool_manager = ToolExecutionManager()
        self.evidence_collector = EvidenceCollector()

    def analyze(self, file_path):

        print("\n===== VAJRA FILE SECURITY PIPELINE =====")

        # Step 1: Basic file analysis
        file_result = self.file_guardian.analyze(
            file_path
        )

        # Step 2: Convert result into standardized evidence
        evidence = self.evidence_collector.create_evidence(
            source="FileGuardian",
            category="file_analysis",
            target=file_path,
            data=file_result,
            severity=file_result["severity"]
        )

        return {
            "file_analysis": file_result,
            "evidence": evidence
        }