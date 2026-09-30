from app.models.ai_backend import AIBackend
from app.models.qualcomm_backend import QualcommBackend
from app.models.genie_x_backend import GenieXBackend


class BackendManager:

    def __init__(self):
        self.development_backend = AIBackend()
        self.qualcomm_backend = QualcommBackend()
        self.geniex_backend = GenieXBackend()

        self.active_backend = "development"

    def set_backend(self, backend_name):

        if backend_name == "qualcomm":

            self.active_backend = "qualcomm"

            # Connect and configure the Qualcomm device
            result = self.qualcomm_backend.configure_device(
                "Snapdragon X Elite CRD"
            )

            return result

        elif backend_name == "geniex":

            self.active_backend = "geniex"

            return {
                "status": "backend_selected",
                "backend": "geniex"
            }

        else:

            self.active_backend = "development"

            return {
                "status": "backend_selected",
                "backend": "development"
            }

    def get_backend(self):

        if self.active_backend == "qualcomm":
            return self.qualcomm_backend

        if self.active_backend == "geniex":
            return self.geniex_backend

        return self.development_backend

    def get_status(self):

        backend = self.get_backend()

        status = backend.get_status()

        status["active_backend"] = self.active_backend

        return status

    def analyze(self, prompt, image=None):

        backend = self.get_backend()

        if self.active_backend == "qualcomm":

            return backend.analyze(
                prompt,
                image
            )

        if self.active_backend == "geniex":

            return backend.analyze(prompt)

        return backend.analyze(prompt)