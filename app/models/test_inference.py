from app.models.model_manager import ModelManager
from app.models.inference_manager import InferenceManager


model_manager = ModelManager()

inference = InferenceManager(model_manager)


result = inference.run(
    "text",
    "Analyze this URL for phishing risk."
)


print("\n===== VAJRA INFERENCE MANAGER =====")

print("Model:", result["model"])
print("Runtime:", result["runtime"])
print("Input Type:", result["input_type"])
print("Status:", result["status"])
print("Latency:", result["latency_ms"], "ms")