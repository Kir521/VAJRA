from app.security.file_guardian import FileGuardian


def main():

    print("\n===== VAJRA FILE GUARDIAN TEST =====")

    guardian = FileGuardian()

    test_file = "README.md"

    result = guardian.analyze(test_file)

    print("\nFile:", result["file"])
    print("Exists:", result["exists"])
    print("Size:", result["size_bytes"], "bytes")
    print("Extension:", result["extension"])
    print("SHA-256:", result["sha256"])
    print("Signals:", result["signals"])
    print("Severity:", result["severity"])


if __name__ == "__main__":
    main()