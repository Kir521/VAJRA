from app.tools.tool_execution_manager import ToolExecutionManager


manager = ToolExecutionManager()

tools = [
    "nmap",
    "yara",
    "clamscan",
    "tshark",
    "curl"
]

print("\n===== VAJRA TOOL EXECUTION MANAGER =====")

for tool in tools:

    result = manager.run_version_check(tool)

    if result["success"]:
        print(f"\n[+] {tool}")
        print(result["output"])
    else:
        print(f"\n[-] {tool}")
        print(result["error"])