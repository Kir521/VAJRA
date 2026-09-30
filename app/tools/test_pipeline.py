from app.tools.security_pipeline import SecurityPipeline


pipeline = SecurityPipeline()

tools = [
    "nmap",
    "yara",
    "clamscan",
    "tshark",
    "curl"
]

print("\n===== VAJRA SECURITY PIPELINE =====")

for tool in tools:

    evidence = pipeline.check_tool(tool)

    print("\nTool:", tool)
    print("Source:", evidence["source"])
    print("Category:", evidence["category"])
    print("Severity:", evidence["severity"])
    print("Data:", evidence["data"])