from app.tools.security_tool_adapter import SecurityToolAdapter


adapter = SecurityToolAdapter()

tools = [
    "nmap",
    "yara",
    "clamscan",
    "tshark",
    "curl"
]

print("\n===== VAJRA SECURITY TOOLS =====")

for tool in tools:

    result = adapter.get_version(tool)

    if result["available"]:
        print(f"[+] {tool}: AVAILABLE")
        print(f"    {result['version']}")
    else:
        print(f"[-] {tool}: NOT FOUND")