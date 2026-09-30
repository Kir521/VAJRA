class ModelManager:

    MODELS = {
        "security_text": {
            "name": "Security Text Model",
            "type": "text",
            "runtime": "development"
        },
        "security_vision": {
            "name": "Qwen3-VL-2B-Instruct",
            "type": "multimodal",
            "runtime": "GenieX"
        }
    }

    def list_models(self):

        return self.MODELS

    def get_model(self, model_id):

        return self.MODELS.get(model_id)

    def select_model(self, input_type):

        if input_type == "image":
            return self.MODELS["security_vision"]

        return self.MODELS["security_text"]