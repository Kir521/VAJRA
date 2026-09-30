from app.models.ai_backend import AIBackend


backend = AIBackend()

status = backend.get_status()

print("\n===== VAJRA AI BACKEND =====")
print("Backend:", status["backend"])
print("Device:", status["device"])
print("NPU:", status["npu"])
print("Status:", status["status"])

result = backend.analyze(
    "Analyze this URL for potential security risks."
)

print("\nAI Analysis Status:", result["status"])