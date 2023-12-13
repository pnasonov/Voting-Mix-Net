from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class Voter:
    def __init__(self,
                 public_key,
                 private_key,
                 public_elgamal,
                 private_elgamal) -> None:
        self.public_key = public_key
        self.private_key = private_key
        self.public_elg = public_elgamal
        self.private_elgamal = private_elgamal

    @staticmethod
    def sign_message(message, private_key) -> bytearray:
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    @staticmethod
    def verify_signature(message, signature, public_key) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False
