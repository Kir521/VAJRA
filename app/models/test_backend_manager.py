from app.models.backend_manager import BackendManager


def main():

    print("\n===== VAJRA BACKEND MANAGER TEST =====")

    manager = BackendManager()

    print("\n--- DEVELOPMENT BACKEND ---")

    print(
        manager.get_status()
    )

    print(
        manager.analyze(
            "Analyze a suspicious URL."
        )
    )

    print("\n--- QUALCOMM BACKEND ---")

    manager.set_backend(
        "qualcomm"
    )

    print(
        manager.get_status()
    )

    print(
        manager.analyze(
            "Analyze a suspicious URL."
        )
    )


if __name__ == "__main__":
    main()