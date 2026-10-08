import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Simulador de Java Keytool desarrollado en Python"
    )

    parser.add_argument(
        "--genkeypair",
        action="store_true",
        help="Genera un nuevo par de claves RSA"
    )

    parser.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de certificado CSR"
    )

    args = parser.parse_args()

    if args.genkeypair:
        print("Has seleccionado --genkeypair")

    elif args.certreq:
        print("Has seleccionado --certreq")


if __name__ == "__main__":
    main()