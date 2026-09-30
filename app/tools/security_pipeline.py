from app.tools.tool_execution_manager import ToolExecutionManager
from app.tools.evidence_collector import EvidenceCollector


class SecurityPipeline:

    def __init__(self):
        self.tool_manager = ToolExecutionManager()
        self.evidence_collector = EvidenceCollector()

    def check_tool(self, tool):

        result = self.tool_manager.run_version_check(tool)

        if result["success"]:

            evidence = self.evidence_collector.create_evidence(
                source=tool,
                category="Tool Verification",
                target=tool,
                data={
                    "output": result["output"]
                },
                severity="INFO"
            )

        else:

            evidence = self.evidence_collector.create_evidence(
                source="VAJRA",
                category="Tool Verification",
                target=tool,
                data={
                    "error": result["error"]
                },
                severity="INFO"
            )

        return evidence