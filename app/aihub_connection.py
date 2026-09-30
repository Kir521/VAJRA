import qai_hub


def check_connection():

    print("\n===== VAJRA QUALCOMM AI HUB =====")
    print("SDK Version:", qai_hub.__version__)

    try:
        devices = qai_hub.get_devices()

        print("\nAI Hub connection: OK")
        print("Total devices:", len(devices))

        print("\n===== SNAPDRAGON DEVICES =====")

        count = 0

        for device in devices:

            name = device.name

            if "Snapdragon" in name:

                print("-", name)
                count += 1

                if count >= 20:
                    break

        print("\nSnapdragon devices shown:", count)

    except Exception as error:

        print("\nAI Hub connection failed.")
        print("Reason:", error)


if __name__ == "__main__":
    check_connection()