"""
Encryption Module

Provides AES encryption in GCM mode with support for:
- AES-128 (16-byte key, faster)
- AES-256 (32-byte key, stronger)

Format: [IV(16 bytes) | TAG(16 bytes) | Ciphertext]
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Tuple


def encrypt_aes_128(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-128-GCM (faster encryption).
    
    Args:
        key: 16-byte key for AES-128
        plaintext: Data to encrypt
        
    Returns:
        Encrypted data: [IV(16 bytes) | TAG(16 bytes) | Ciphertext]
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)}")
    
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext


def decrypt_aes_128(key: bytes, data: bytes) -> bytes:
    """
    Decrypts AES-128-GCM encrypted data.
    
    Args:
        key: 16-byte key for AES-128
        data: Encrypted data in format [IV(16) | TAG(16) | Ciphertext]
        
    Returns:
        Decrypted plaintext
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)}")
    
    iv = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_aes_256(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM (stronger encryption).
    
    Args:
        key: 32-byte key for AES-256
        plaintext: Data to encrypt
        
    Returns:
        Encrypted data: [IV(16 bytes) | TAG(16 bytes) | Ciphertext]
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
    
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext


def decrypt_aes_256(key: bytes, data: bytes) -> bytes:
    """
    Decrypts AES-256-GCM encrypted data.
    
    Args:
        key: 32-byte key for AES-256
        data: Encrypted data in format [IV(16) | TAG(16) | Ciphertext]
        
    Returns:
        Decrypted plaintext
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
    
    iv = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM (default, stronger).
    Returns: [IV(16 bytes) | TAG(16 bytes) | Ciphertext]
    
    This is the default encryption method using AES-256.
    For adaptive encryption, use encrypt_aes_128() or encrypt_aes_256() directly.
    """
    return encrypt_aes_256(key, plaintext)


def decrypt_data(key: bytes, data: bytes) -> bytes:
    """
    Decrypts AES-256-GCM encrypted data (default).
    Expects data from the format [IV(16) | TAG(16) | Ciphertext].
    
    This is the default decryption method using AES-256.
    For adaptive decryption, use decrypt_aes_128() or decrypt_aes_256() directly.
    """
    return decrypt_aes_256(key, data)
