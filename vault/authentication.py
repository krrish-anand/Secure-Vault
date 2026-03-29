import os
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

SALT_SIZE = 16  # 16 bytes

def generate_salt(size: int = SALT_SIZE) -> bytes:
    """
    Generates a cryptographically secure random salt of given size.
    """
    return os.urandom(size)

def derive_key(password: str, salt: bytes, iterations: int = 100_000, key_size: int = 32) -> bytes:
    """
    Derives a key using PBKDF2 with SHA-256.
    :param password: User's password (string)
    :param salt: Random salt bytes
    :param iterations: Number of PBKDF2 iterations
    :param key_size: Length of derived key (bytes)
    :return: Derived key (bytes)
    """
    return PBKDF2(
        password,
        salt,
        dkLen=key_size,
        count=iterations,
        hmac_hash_module=SHA256
    )
