import qai_hub as hub


class QualcommBackend:

    def __init__(self):

        self.provider = "Qualcomm AI Hub"
        self.runtime = "GenieX"

        self.device = None
        self.available = False

        self.client = None
        self.last_error = None

    # =========================================
    # CONNECT TO AI HUB
    # =========================================

    def connect(self):

        try:

            self.client = hub.Client()

            self.available = True
            self.last_error = None

            return {
                "status": "connected",
                "provider": self.provider,
                "runtime": self.runtime
            }

        except Exception as error:

            self.available = False
            self.last_error = str(error)

            return {
                "status": "connection_failed",
                "provider": self.provider,
                "error": str(error)
            }

    # =========================================
    # CONFIGURE DEVICE
    # =========================================

    def configure_device(self, device_name):

        if self.client is None:

            connection = self.connect()

            if connection["status"] != "connected":
                return connection

        try:

            devices = self.client.get_devices()

            matching_device = None

            for device in devices:

                if device.name == device_name:

                    matching_device = device
                    break

            if matching_device is None:

                return {
                    "status": "device_not_found",
                    "device": device_name
                }

            self.device = matching_device
            self.available = True

            return {
                "status": "device_configured",
                "device": matching_device.name
            }

        except Exception as error:

            self.last_error = str(error)

            return {
                "status": "device_configuration_failed",
                "error": str(error)
            }

    # =========================================
    # STATUS
    # =========================================

    def get_status(self):

        return {
            "provider": self.provider,
            "runtime": self.runtime,
            "device": (
                self.device.name
                if self.device
                else None
            ),
            "available": self.available,
            "connected": self.client is not None,
            "error": self.last_error
        }

    # =========================================
    # AI ANALYSIS
    # =========================================

    def analyze(self, prompt, image=None):

        if self.client is None:

            connection = self.connect()

            if connection["status"] != "connected":
                return connection

        if self.device is None:

            return {
                "status": "device_not_configured",
                "message": (
                    "Configure a Qualcomm AI Hub device first."
                )
            }

        return {
            "status": "geniex_ready",
            "provider": self.provider,
            "runtime": self.runtime,
            "model": "Qwen3.5-2B",
            "model_id": "unsloth/Qwen3.5-2B-GGUF",
            "device": self.device.name,
            "input": {
                "prompt": prompt,
                "image_provided": image is not None
            },
            "execution": "deployment_pending",
            "message": (
                "GenieX inference is configured for "
                "Snapdragon deployment."
            )
        }