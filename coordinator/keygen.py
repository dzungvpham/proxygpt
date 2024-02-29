# python keygen.py [rsa|ed25519] -o keys.txt
import argparse
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519


def generate_private_key(algorithm, bits=2048):
    if algorithm == "rsa":
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=bits, backend=default_backend()
        )
    elif algorithm == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError("Invalid algorithm. Choose 'rsa' or 'ed25519'.")

    return private_key


def save_key_to_file(private_key, public_key, filename):
    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(filename, "wb") as f:
        f.write(base64.b64encode(serialized_private_key) + b"\n")
        f.write(base64.b64encode(serialized_public_key) + b"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate and save RSA or Ed25519 key pair."
    )
    parser.add_argument(
        "algorithm",
        choices=["rsa", "ed25519"],
        help="Specify 'rsa' or 'ed25519' algorithm.",
    )
    parser.add_argument(
        "--output", "-o", required=True, help="Output file for the keys."
    )

    args = parser.parse_args()
    private_key = generate_private_key(args.algorithm)
    public_key = private_key.public_key()
    save_key_to_file(private_key, public_key, args.output)
    print(f"Keys saved to {args.output}")
