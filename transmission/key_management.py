"""
RSA-2048 Key Management Module
Handles RSA key generation, encryption/decryption, and digital signatures
for secure key exchange in transmission system.

Security Note:
- Uses RSA-2048 (128-byte keys, ~112-bit security)
- OAEP padding with SHA-256 for encryption
- PSS padding with SHA-256 for signatures
- Session keys encrypted with RSA before transmission
"""

import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path


class KeyManager:
    """
    Manages RSA-2048 key pair generation, storage, encryption/decryption,
    and digital signing for transmission system.
    
    Architecture:
    - Sender: Has private key (for signing), receiver's public key (for encrypting session key)
    - Receiver: Has private key (for decryption), sender's public key (for signature verification)
    """

    # RSA Configuration
    RSA_KEY_SIZE = 2048
    RSA_E = 65537  # Standard public exponent
    HASH_ALGORITHM = hashes.SHA256()

    def __init__(self, key_dir: str = "data/keys"):
        """
        Initialize KeyManager with optional key directory.
        
        Args:
            key_dir: Directory to store/load RSA keys (default: data/keys)
        """
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.backend = default_backend()
        
        # In-memory key storage
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None  # Other party's public key for encryption

    def generate_key_pair(self) -> tuple:
        """
        Generate a new RSA-2048 key pair.
        
        Returns:
            tuple: (private_key, public_key) as cryptography objects
        """
        private_key = rsa.generate_private_key(
            public_exponent=self.RSA_E,
            key_size=self.RSA_KEY_SIZE,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        self.private_key = private_key
        self.public_key = public_key
        
        print(f"✓ Generated RSA-{self.RSA_KEY_SIZE} key pair")
        return private_key, public_key

    def save_private_key(self, filename: str, password: bytes = None) -> bool:
        """
        Save private key to PEM file (optionally encrypted with password).
        
        Args:
            filename: Name of file in key_dir
            password: Optional bytes password for encryption
            
        Returns:
            bool: True if successful
        """
        if not self.private_key:
            print("✗ No private key to save")
            return False
        
        filepath = self.key_dir / filename
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open(filepath, "wb") as f:
            f.write(pem)
        
        print(f"✓ Saved private key to {filename}")
        return True

    def save_public_key(self, filename: str) -> bool:
        """
        Save public key to PEM file.
        
        Args:
            filename: Name of file in key_dir
            
        Returns:
            bool: True if successful
        """
        if not self.public_key:
            print("✗ No public key to save")
            return False
        
        filepath = self.key_dir / filename
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filepath, "wb") as f:
            f.write(pem)
        
        print(f"✓ Saved public key to {filename}")
        return True

    def load_private_key(self, filename: str, password: bytes = None) -> bool:
        """
        Load private key from PEM file.
        
        Args:
            filename: Name of file in key_dir
            password: Optional bytes password for decryption
            
        Returns:
            bool: True if successful
        """
        filepath = self.key_dir / filename
        
        if not filepath.exists():
            print(f"✗ Private key file not found: {filename}")
            return False
        
        with open(filepath, "rb") as f:
            pem_data = f.read()
        
        try:
            self.private_key = serialization.load_pem_private_key(
                pem_data,
                password=password,
                backend=self.backend
            )
            self.public_key = self.private_key.public_key()
            print(f"✓ Loaded private key from {filename}")
            return True
        except Exception as e:
            print(f"✗ Failed to load private key: {e}")
            return False

    def load_public_key(self, filename: str, as_peer: bool = False) -> bool:
        """
        Load public key from PEM file.
        
        Args:
            filename: Name of file in key_dir
            as_peer: If True, store as peer_public_key for encryption
            
        Returns:
            bool: True if successful
        """
        filepath = self.key_dir / filename
        
        if not filepath.exists():
            print(f"✗ Public key file not found: {filename}")
            return False
        
        with open(filepath, "rb") as f:
            pem_data = f.read()
        
        try:
            public_key = serialization.load_pem_public_key(
                pem_data,
                backend=self.backend
            )
            
            if as_peer:
                self.peer_public_key = public_key
                print(f"✓ Loaded peer public key from {filename}")
            else:
                self.public_key = public_key
                print(f"✓ Loaded public key from {filename}")
            
            return True
        except Exception as e:
            print(f"✗ Failed to load public key: {e}")
            return False

    def encrypt_with_public_key(self, data: bytes, public_key=None) -> bytes:
        """
        Encrypt data using RSA-OAEP with SHA-256 (for session key encryption).
        
        Args:
            data: Bytes to encrypt (max 190 bytes for 2048-bit key)
            public_key: Public key to use (default: peer_public_key)
            
        Returns:
            bytes: Encrypted data (256 bytes for 2048-bit key)
        """
        key = public_key or self.peer_public_key
        if not key:
            raise ValueError("No public key available for encryption")
        
        ciphertext = key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.HASH_ALGORITHM),
                algorithm=self.HASH_ALGORITHM,
                label=b"transmission_session_key"
            )
        )
        
        return ciphertext

    def decrypt_with_private_key(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using RSA-OAEP with SHA-256.
        
        Args:
            ciphertext: Encrypted bytes to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        if not self.private_key:
            raise ValueError("No private key available for decryption")
        
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.HASH_ALGORITHM),
                algorithm=self.HASH_ALGORITHM,
                label=b"transmission_session_key"
            )
        )
        
        return plaintext

    def sign_data(self, data: bytes) -> bytes:
        """
        Create digital signature using RSA-PSS with SHA-256.
        
        Args:
            data: Bytes to sign
            
        Returns:
            bytes: Signature (256 bytes for 2048-bit key)
        """
        if not self.private_key:
            raise ValueError("No private key available for signing")
        
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(self.HASH_ALGORITHM),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self.HASH_ALGORITHM
        )
        
        return signature

    def verify_signature(self, data: bytes, signature: bytes, public_key=None) -> bool:
        """
        Verify digital signature using RSA-PSS with SHA-256.
        
        Args:
            data: Original data bytes
            signature: Signature bytes to verify
            public_key: Public key to use (default: peer_public_key)
            
        Returns:
            bool: True if signature is valid
        """
        key = public_key or self.peer_public_key
        if not key:
            print("✗ No public key available for verification")
            return False
        
        try:
            key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(self.HASH_ALGORITHM),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self.HASH_ALGORITHM
            )
            return True
        except Exception:
            return False

    def get_public_key_pem(self) -> str:
        """
        Get public key as PEM-formatted string for transmission.
        
        Returns:
            str: PEM-encoded public key
        """
        if not self.public_key:
            return ""
        
        pem_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem_bytes.decode('utf-8')

    def load_public_key_from_pem(self, pem_str: str, as_peer: bool = False) -> bool:
        """
        Load public key from PEM string (received over network).
        
        Args:
            pem_str: PEM-encoded public key string
            as_peer: If True, store as peer_public_key
            
        Returns:
            bool: True if successful
        """
        try:
            public_key = serialization.load_pem_public_key(
                pem_str.encode('utf-8'),
                backend=self.backend
            )
            
            if as_peer:
                self.peer_public_key = public_key
            else:
                self.public_key = public_key
            
            return True
        except Exception as e:
            print(f"✗ Failed to load public key from PEM: {e}")
            return False

    def get_key_info(self) -> dict:
        """
        Get information about current keys.
        
        Returns:
            dict: Key information and status
        """
        return {
            "private_key_loaded": self.private_key is not None,
            "public_key_loaded": self.public_key is not None,
            "peer_public_key_loaded": self.peer_public_key is not None,
            "key_size": self.RSA_KEY_SIZE,
            "hash_algorithm": "SHA-256",
            "encryption_scheme": "RSA-OAEP",
            "signature_scheme": "RSA-PSS"
        }


class SessionKeyManager:
    """
    Manages session-specific AES keys encrypted with RSA.
    Each transmission session uses a unique AES key that is:
    1. Generated randomly
    2. Encrypted with receiver's RSA public key
    3. Transmitted securely
    4. Decrypted with receiver's RSA private key
    """

    def __init__(self, key_manager: KeyManager):
        """
        Initialize SessionKeyManager with a KeyManager instance.
        
        Args:
            key_manager: KeyManager instance for RSA operations
        """
        self.key_manager = key_manager
        self.session_keys = {}  # session_id -> aes_key mapping

    def generate_aes_session_key(self, key_size: int = 32) -> bytes:
        """
        Generate a random AES session key.
        
        Args:
            key_size: Size in bytes (32 for AES-256, 16 for AES-128)
            
        Returns:
            bytes: Random key suitable for AES
        """
        session_key = os.urandom(key_size)
        return session_key

    def encrypt_session_key(self, session_key: bytes) -> bytes:
        """
        Encrypt AES session key with receiver's RSA public key.
        
        Args:
            session_key: AES key to encrypt
            
        Returns:
            bytes: RSA-encrypted session key
        """
        encrypted = self.key_manager.encrypt_with_public_key(session_key)
        return encrypted

    def decrypt_session_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt AES session key with private RSA key.
        
        Args:
            encrypted_key: RSA-encrypted session key
            
        Returns:
            bytes: Decrypted AES key
        """
        decrypted = self.key_manager.decrypt_with_private_key(encrypted_key)
        return decrypted

    def store_session_key(self, session_id: str, aes_key: bytes) -> None:
        """
        Store session key in memory (for reference).
        
        Args:
            session_id: Unique session identifier
            aes_key: AES key bytes
        """
        self.session_keys[session_id] = aes_key

    def get_session_key(self, session_id: str) -> bytes:
        """
        Retrieve stored session key.
        
        Args:
            session_id: Session identifier
            
        Returns:
            bytes: AES key or None if not found
        """
        return self.session_keys.get(session_id)


if __name__ == "__main__":
    # ============================================================================
    # Demo: RSA Key Management and Session Key Exchange
    # ============================================================================
    print("\n" + "="*70)
    print("RSA-2048 KEY MANAGEMENT DEMO")
    print("="*70 + "\n")

    # 1. Create sender and receiver key managers
    print("STEP 1: Generate RSA-2048 Key Pairs")
    print("-" * 70)
    sender_km = KeyManager("data/keys/sender")
    receiver_km = KeyManager("data/keys/receiver")

    sender_km.generate_key_pair()
    receiver_km.generate_key_pair()

    # 2. Save keys
    print("\nSTEP 2: Save Keys to Files")
    print("-" * 70)
    sender_km.save_private_key("sender_private.pem")
    sender_km.save_public_key("sender_public.pem")
    receiver_km.save_private_key("receiver_private.pem")
    receiver_km.save_public_key("receiver_public.pem")

    # 3. Exchange public keys (in real system: over network)
    print("\nSTEP 3: Exchange Public Keys")
    print("-" * 70)
    # Get PEM-formatted public keys (would be transmitted over network)
    sender_public_pem = sender_km.get_public_key_pem()
    receiver_public_pem = receiver_km.get_public_key_pem()
    
    # Load as peer (in real system, would receive from network)
    sender_km.load_public_key_from_pem(receiver_public_pem, as_peer=True)
    receiver_km.load_public_key_from_pem(sender_public_pem, as_peer=True)
    print("✓ Public keys exchanged securely (PEM format)")

    # 4. Session key encryption
    print("\nSTEP 4: Generate and Encrypt Session Key")
    print("-" * 70)
    session_km = SessionKeyManager(sender_km)
    
    # Sender generates AES session key
    session_key = session_km.generate_aes_session_key(32)
    print(f"✓ Generated AES-256 session key: {session_key.hex()[:32]}...")
    
    # Sender encrypts with receiver's public key
    encrypted_session_key = session_km.encrypt_session_key(session_key)
    print(f"✓ Encrypted with RSA: {encrypted_session_key.hex()[:32]}... ({len(encrypted_session_key)} bytes)")

    # 5. Receiver decrypts session key
    print("\nSTEP 5: Receiver Decrypts Session Key")
    print("-" * 70)
    receiver_session_km = SessionKeyManager(receiver_km)
    decrypted_key = receiver_session_km.decrypt_session_key(encrypted_session_key)
    
    if decrypted_key == session_key:
        print("✓ Session key decrypted successfully!")
        print(f"✓ Keys match: {decrypted_key.hex()[:32]}...")
    else:
        print("✗ Session key mismatch!")

    # 6. Digital signatures
    print("\nSTEP 6: Digital Signature Demo")
    print("-" * 70)
    
    # Sender signs a message
    message = b"Secure transmission session initiated"
    signature = sender_km.sign_data(message)
    print(f"✓ Message: {message.decode()}")
    print(f"✓ Signature: {signature.hex()[:32]}... ({len(signature)} bytes)")
    
    # Receiver verifies signature
    is_valid = receiver_km.verify_signature(message, signature, sender_km.public_key)
    print(f"✓ Signature verified: {is_valid}")

    # 7. Key info
    print("\nSTEP 7: Key Information")
    print("-" * 70)
    info = sender_km.get_key_info()
    for key, value in info.items():
        print(f"  {key}: {value}")

    print("\n" + "="*70)
    print("✅ RSA KEY MANAGEMENT DEMO COMPLETE")
    print("="*70 + "\n")
