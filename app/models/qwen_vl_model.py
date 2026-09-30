from app.models.base_model import BaseAIModel


class QwenVLModel(BaseAIModel):
    def __init__(self):
        self.model_name = "Qwen3.5-2B"
        self.model_id = "unsloth/Qwen3.5-2B-GGUF"
        self.runtime = "GenieX"
        self.execution = "deployment_pending"

    def analyze(self, prompt, image=None):
        return {
            "model": self.model_name,
            "model_id": self.model_id,
            "runtime": self.runtime,
            "execution": self.execution,
            "input": {
                "prompt": prompt,
                "image": image
            },
            "status": "geniex_ready"
        }