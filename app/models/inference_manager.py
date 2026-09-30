import time

from app.models.backend_manager import BackendManager


class InferenceManager:

    def __init__(self, model_manager, backend_manager=None):
        self.model_manager = model_manager

        if backend_manager is None:
            self.backend_manager = BackendManager()
        else:
            self.backend_manager = backend_manager

    def run(self, input_type, data):

        model = self._select_model(input_type)

        start_time = time.perf_counter()

        prompt = self._build_prompt(
            input_type,
            data
        )

        image = None

        if isinstance(data, dict):
            image = data.get("image")

        backend_result = self.backend_manager.analyze(
            prompt=prompt,
            image=image
        )

        analysis = self._prepare_analysis(
            input_type,
            data
        )

        end_time = time.perf_counter()

        latency_ms = (
            end_time - start_time
        ) * 1000

        backend_status = backend_result.get(
            "status",
            "unknown"
        )

        return {
            "status": "ready",
            "model": model["name"],
            "runtime": model["runtime"],
            "input_type": input_type,

            "backend": self.backend_manager.active_backend,
            "backend_status": backend_status,
            "backend_response": backend_result,

            "analysis": analysis,

            "latency_ms": round(
                latency_ms,
                3
            )
        }

    def _select_model(self, input_type):

        if self.backend_manager.active_backend in [
            "qualcomm",
            "geniex"
        ]:
            return {
                "name": "Qwen3.5-2B",
                "runtime": "GenieX",
                "type": "multimodal"
            }

        return self.model_manager.select_model(
            input_type
        )

    def _build_prompt(self, input_type, data):

        return (
            "Analyze this security input for VAJRA. "
            "Identify potential security risks, "
            "suspicious behavior, and recommended action.\n\n"
            f"Input type: {input_type}\n"
            f"Input data: {data}"
        )

    def _prepare_analysis(self, input_type, data):

        if input_type == "text":
            return {
                "type": "text_analysis",
                "message": (
                    "Text input prepared "
                    "for AI analysis."
                )
            }

        elif input_type == "image":
            return {
                "type": "vision_analysis",
                "message": (
                    "Image input prepared "
                    "for multimodal AI analysis."
                )
            }

        elif input_type == "url":
            return {
                "type": "url_analysis",
                "message": (
                    "URL input prepared "
                    "for security analysis."
                )
            }

        elif input_type == "file":
            return {
                "type": "file_analysis",
                "message": (
                    "File input prepared "
                    "for security analysis."
                )
            }

        else:
            return {
                "type": "generic_analysis",
                "message": (
                    "Input prepared "
                    "for AI analysis."
                )
            }