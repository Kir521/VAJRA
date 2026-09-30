from app.models.qwen_vl_model import QwenVLModel


model = QwenVLModel()

result = model.analyze(
    "Analyze this security event and identify possible risks."
)

print("\n===== VAJRA AI MODEL =====")
print("Model:", result["model"])
print("Runtime:", result["runtime"])
print("Execution:", result["execution"])
print("Status:", result["status"])