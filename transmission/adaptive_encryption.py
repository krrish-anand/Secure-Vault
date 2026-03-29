"""
Adaptive Encryption Module

Intelligently selects encryption strength based on network conditions.
- GOOD network (latency <50ms): AES-256 (stronger)
- MODERATE network: AES-256 (balanced)
- POOR network (latency >100ms): AES-128 (faster)

Hybrid approach: Encrypts data with AES, secures key with RSA (optional).
"""

from transmission.network_intelligence import NetworkMonitor, NetworkQuality
from vault.encryption import encrypt_aes_128, decrypt_aes_128, encrypt_aes_256, decrypt_aes_256
from typing import Tuple, Optional
from enum import Enum


class EncryptionStrength(Enum):
    """Encryption strength levels."""
    WEAK = "AES-128"      # 128-bit, faster
    STRONG = "AES-256"    # 256-bit, stronger


class AdaptiveEncryptor:
    """
    Selects and applies encryption based on network quality.
    
    Rules:
    - GOOD network (latency <50ms) → AES-256 (stronger)
    - MODERATE network (latency 50-100ms) → AES-256 (balanced, still strong)
    - POOR network (latency >100ms) → AES-128 (faster for degraded connections)
    """

    def __init__(self, network_monitor: Optional[NetworkMonitor] = None):
        """
        Initialize adaptive encryptor.
        
        Args:
            network_monitor: NetworkMonitor instance (auto-create if not provided)
        """
        self.network_monitor = network_monitor or NetworkMonitor()
        self.block_encryption_method = {}  # Maps block_id -> encryption method used
        self.encryption_stats = {
            "aes_128_blocks": 0,
            "aes_256_blocks": 0,
            "total_bytes_encrypted": 0
        }

    def choose_encryption_strength(self,
                                   good_threshold_ms: float = 50.0,
                                   poor_threshold_ms: float = 100.0) -> EncryptionStrength:
        """
        Choose encryption strength based on network quality.
        
        Args:
            good_threshold_ms: Latency threshold for GOOD network (default: 50ms)
            poor_threshold_ms: Latency threshold for POOR network (default: 100ms)
            
        Returns:
            EncryptionStrength (WEAK for AES-128, STRONG for AES-256)
        """
        # Get current network quality
        metrics = self.network_monitor.calculate_metrics()
        
        # Decision logic
        if metrics.avg_latency_ms > poor_threshold_ms:
            # POOR network: use AES-128 (faster)
            return EncryptionStrength.WEAK
        else:
            # GOOD or MODERATE: use AES-256 (stronger)
            return EncryptionStrength.STRONG

    def get_network_quality(self) -> NetworkQuality:
        """Get current network quality classification."""
        return self.network_monitor.get_network_quality()

    def encrypt_block(self, block_id: int, block_data: bytes, 
                     encryption_key: bytes,
                     force_strength: Optional[EncryptionStrength] = None) -> Tuple[bytes, str]:
        """
        Encrypt a block with adaptive strength selection.
        
        Args:
            block_id: Block identifier
            block_data: Block plaintext data
            encryption_key: Master encryption key (32 bytes)
            force_strength: Override automatic selection (for testing)
            
        Returns:
            Tuple of (encrypted_data, encryption_method_used)
            
        Raises:
            ValueError: If encryption_key size doesn't match chosen method
        """
        # Choose encryption strength
        if force_strength:
            strength = force_strength
        else:
            strength = self.choose_encryption_strength()
        
        # Encrypt based on chosen strength
        if strength == EncryptionStrength.WEAK:
            # AES-128: use first 16 bytes of key
            key_128 = encryption_key[:16]
            encrypted_data = encrypt_aes_128(key_128, block_data)
            method = "AES-128"
            self.encryption_stats["aes_128_blocks"] += 1
            
        else:  # EncryptionStrength.STRONG
            # AES-256: use full 32-byte key
            key_256 = encryption_key[:32] if len(encryption_key) >= 32 else encryption_key
            encrypted_data = encrypt_aes_256(key_256, block_data)
            method = "AES-256"
            self.encryption_stats["aes_256_blocks"] += 1
        
        # Track which method was used for this block
        self.block_encryption_method[block_id] = method
        self.encryption_stats["total_bytes_encrypted"] += len(block_data)
        
        return encrypted_data, method

    def decrypt_block(self, block_id: int, encrypted_data: bytes,
                     encryption_key: bytes,
                     method: str) -> bytes:
        """
        Decrypt a block using the specified method.
        
        Args:
            block_id: Block identifier
            encrypted_data: Encrypted block data
            encryption_key: Master encryption key (32 bytes)
            method: Encryption method used ("AES-128" or "AES-256")
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            ValueError: If method is unknown or key size invalid
        """
        if method == "AES-128":
            # AES-128: use first 16 bytes of key
            key_128 = encryption_key[:16]
            plaintext = decrypt_aes_128(key_128, encrypted_data)
            
        elif method == "AES-256":
            # AES-256: use full 32-byte key
            key_256 = encryption_key[:32] if len(encryption_key) >= 32 else encryption_key
            plaintext = decrypt_aes_256(key_256, encrypted_data)
            
        else:
            raise ValueError(f"Unknown encryption method: {method}")
        
        return plaintext

    def get_block_encryption_method(self, block_id: int) -> Optional[str]:
        """Get encryption method used for a block."""
        return self.block_encryption_method.get(block_id)

    def measure_network(self, sample_count: int = 5) -> None:
        """
        Measure network conditions to inform encryption decisions.
        
        Args:
            sample_count: Number of latency samples to collect
        """
        self.network_monitor.measure_latency(sample_count=sample_count)

    def get_current_metrics(self) -> dict:
        """Get current network metrics for display."""
        metrics = self.network_monitor.calculate_metrics()
        return {
            "latency_ms": metrics.avg_latency_ms,
            "packet_loss_percent": metrics.packet_loss_percent,
            "network_quality": metrics.quality.value,
            "sample_count": metrics.sample_count
        }

    def get_encryption_summary(self) -> str:
        """Get summary of encryption statistics."""
        return (
            f"AES-128 blocks: {self.encryption_stats['aes_128_blocks']}, "
            f"AES-256 blocks: {self.encryption_stats['aes_256_blocks']}, "
            f"Total encrypted: {self.encryption_stats['total_bytes_encrypted']} bytes"
        )

    def reset_stats(self):
        """Clear encryption statistics."""
        self.encryption_stats = {
            "aes_128_blocks": 0,
            "aes_256_blocks": 0,
            "total_bytes_encrypted": 0
        }
        self.block_encryption_method.clear()
