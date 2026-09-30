from app.models.base_model import BaseAIModel



class LocalAIModel(BaseAIModel):

    def analyze(self, data):

        return {
            "model": "VAJRA-Local-Model",
            "status": "ready",
            "execution": "local"
        }