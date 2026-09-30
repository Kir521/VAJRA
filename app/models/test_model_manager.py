from app.models.model_manager import ModelManager


manager = ModelManager()

print("\n===== VAJRA MODEL MANAGER =====")

print("\nAvailable Models:")

for model_id, model in manager.list_models().items():
    print(
        f"- {model_id}: "
        f"{model['name']} "
        f"({model['type']})"
    )


print("\nText Input:")

text_model = manager.select_model("text")
print(text_model)


print("\nImage Input:")

vision_model = manager.select_model("image")
print(vision_model)