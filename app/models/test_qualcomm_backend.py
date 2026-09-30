from app.models.qualcomm_backend import QualcommBackend


def main():

    print("\n===== VAJRA QUALCOMM BACKEND TEST =====")

    backend = QualcommBackend()

    print("\nInitial Status:")
    print(backend.get_status())

    backend.configure_device(
        "Snapdragon Development Target"
    )

    print("\nConfigured Status:")
    print(backend.get_status())

    result = backend.analyze(
        prompt="Analyze this security event."
    )

    print("\nAnalysis:")
    print(result)


if __name__ == "__main__":
    main()