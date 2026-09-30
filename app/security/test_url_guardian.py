from app.security.url_guardian import URLGuardian


def main():
    guardian = URLGuardian()

    tests = [
        "https://example.com",
        "http://example.com/login",
        "https://user@example.com:8080/login",
        "https://xn--example-9za.com",
        "http://192.168.1.10/login",
        "https://example.com/a%20b",
        "https://a.b.c.d.example.com/login",
    ]

    for url in tests:
        print("\nURL:", url)
        result = guardian.analyze(url)
        print(result)


if __name__ == "__main__":
    main()
