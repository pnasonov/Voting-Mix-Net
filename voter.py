from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class Voter:

    def __init__(self,
                 private_key,
                 public_key,
                 private_elgamal,
                 public_elgamal, ) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.private_elgamal = private_elgamal
        self.public_elgamal = public_elgamal

        self.choice = None
        self.random_lines = []
        self.en_a = None
        self.en_b = None
        self.en_c = None
        self.en_d = None
        self.decrypted = []
        self.subscribed = []
        self.result = []

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
