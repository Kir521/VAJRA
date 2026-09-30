from app.models.inference_manager import InferenceManager


class MultimodalSecurityAnalyzer:

    def __init__(self, model_manager):

        self.inference_manager = InferenceManager(
            model_manager
        )

    def analyze(
        self,
        text=None,
        image=None,
        url=None,
        evidence=None
    ):

        inputs = {}

        if text:
            inputs["text"] = text

        if image:
            inputs["image"] = image

        if url:
            inputs["url"] = url

        if evidence:
            inputs["evidence"] = evidence

        # Select the appropriate input type
        if image:
            input_type = "image"
        elif url:
            input_type = "url"
        else:
            input_type = "text"

        result = self.inference_manager.run(
            input_type=input_type,
            data=inputs
        )

        return {
            "module": "Multimodal Security Analyzer",
            "input_type": input_type,
            "inputs": inputs,
            "model": result["model"],
            "runtime": result["runtime"],
            "analysis": result["analysis"],
            "status": result["status"],
            "latency_ms": result["latency_ms"]
        }