import secrets

from voter import Voter
from crypto_utils import (
    generate_rsa_keys,
    generate_elgamal_keys
)


def voting() -> None:
    voters = []

    # Створення виборців і присвоєння їм RSA та Elgamal ключів
    for _ in range(4):
        voters.append(Voter(*generate_rsa_keys(), *generate_elgamal_keys()))

    # Генерація випадкових рядків для бюлетенів
    for voter in voters:
        voter.random_lines = [
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
        ]
