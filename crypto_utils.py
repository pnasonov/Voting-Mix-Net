from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import secrets
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ec
from collections import Counter


def generate_rsa_keys() -> (bytes, bytes):
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key


def generate_aes_key() -> (bytes, bytes):
    return secrets.token_bytes(16)


def encrypt_message(message, public_key) -> bytes:
    aes_key = generate_aes_key()
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    return encrypted_aes_key + cipher_aes.nonce + tag + ciphertext


def decrypt_message(encrypted_message, private_key) -> bytes:
    encrypted_aes_key = encrypted_message[:128]
    nonce = encrypted_message[128:144]
    tag = encrypted_message[144:160]
    ciphertext = encrypted_message[160:]
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message


def generate_elgamal_keys() -> (bytes, bytes):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    return private_key, public_key


def count_votes(votes) -> str | list:
    vote_counts = Counter(votes)
    max_votes = max(vote_counts.values())
    winners = [candidate for candidate, count in vote_counts.items() if count == max_votes]

    if len(winners) == 1:
        return winners[0]
    else:
        return winners
