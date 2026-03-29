"""
Block Hasher Module

Computes SHA-256 hashes for each block.
Provides verification and blockchain registration.
"""

import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass
from transmission.block_splitter import BlockMetadata


@dataclass
class BlockHash:
    """Container for block hash information."""
    block_id: int
    hash: str          # SHA-256 hex digest
    plaintext_size: int
    encrypted_size: Optional[int] = None


class BlockHasher:
    """
    Computes and manages SHA-256 hashes for file blocks.
    Stores hashes by block_id for quick lookup and verification.
    """

    def __init__(self):
        """Initialize block hasher with empty hash registry."""
        self.block_hashes: Dict[int, BlockHash] = {}
        self.block_metadata: Dict[int, BlockMetadata] = {}

    def hash_block(self, block_id: int, block_data: bytes, plaintext_size: int) -> str:
        """
        Compute SHA-256 hash of block data.
        
        Args:
            block_id: Block identifier
            block_data: Block data to hash
            plaintext_size: Original unencrypted size (for reference)
            
        Returns:
            SHA-256 hex digest
        """
        hash_obj = hashlib.sha256(block_data)
        hash_hex = hash_obj.hexdigest()
        
        # Store in registry
        self.block_hashes[block_id] = BlockHash(
            block_id=block_id,
            hash=hash_hex,
            plaintext_size=plaintext_size,
            encrypted_size=len(block_data)
        )
        
        return hash_hex

    def verify_block(self, block_id: int, block_data: bytes) -> bool:
        """
        Verify block data against stored hash.
        
        Args:
            block_id: Block identifier
            block_data: Block data to verify
            
        Returns:
            True if hash matches, False otherwise
        """
        if block_id not in self.block_hashes:
            return False
        
        # Recompute hash
        hash_obj = hashlib.sha256(block_data)
        computed_hash = hash_obj.hexdigest()
        
        # Compare with stored hash
        stored_hash = self.block_hashes[block_id].hash
        return computed_hash == stored_hash

    def get_hash(self, block_id: int) -> Optional[str]:
        """
        Get stored hash for a block.
        
        Args:
            block_id: Block identifier
            
        Returns:
            SHA-256 hex digest or None if not found
        """
        if block_id in self.block_hashes:
            return self.block_hashes[block_id].hash
        return None

    def get_all_hashes(self) -> Dict[int, str]:
        """
        Get all block hashes as dict.
        
        Returns:
            Dictionary mapping block_id -> hash
        """
        return {bid: bh.hash for bid, bh in self.block_hashes.items()}

    def register_block_metadata(self, block: BlockMetadata):
        """
        Register block metadata for cross-reference.
        
        Args:
            block: BlockMetadata object
        """
        self.block_metadata[block.block_id] = block

    def register_blocks(self, blocks: List[BlockMetadata]):
        """
        Register multiple block metadata objects.
        
        Args:
            blocks: List of BlockMetadata objects
        """
        for block in blocks:
            self.register_block_metadata(block)

    def get_block_info(self, block_id: int) -> Optional[Dict]:
        """
        Get combined hash and metadata for a block.
        
        Args:
            block_id: Block identifier
            
        Returns:
            Dict with hash, size, offset info or None if not found
        """
        if block_id not in self.block_hashes:
            return None
        
        block_hash = self.block_hashes[block_id]
        block_meta = self.block_metadata.get(block_id)
        
        info = {
            "block_id": block_id,
            "hash": block_hash.hash,
            "plaintext_size": block_hash.plaintext_size,
            "encrypted_size": block_hash.encrypted_size,
        }
        
        if block_meta:
            info.update({
                "offset": block_meta.offset,
                "sequence": block_meta.sequence,
            })
        
        return info

    def get_missing_hashes(self, block_ids: List[int]) -> List[int]:
        """
        Find block IDs without computed hashes.
        
        Args:
            block_ids: List of expected block IDs
            
        Returns:
            List of block IDs that don't have hashes yet
        """
        missing = []
        for block_id in block_ids:
            if block_id not in self.block_hashes:
                missing.append(block_id)
        return missing

    def clear(self):
        """Clear all stored hashes and metadata."""
        self.block_hashes.clear()
        self.block_metadata.clear()

    def get_summary(self) -> str:
        """Get human-readable summary of hashes."""
        return (
            f"Hashed Blocks: {len(self.block_hashes)} | "
            f"Registered Metadata: {len(self.block_metadata)}"
        )

    def export_hashes(self) -> Dict[int, str]:
        """
        Export hashes for blockchain or persistence.
        
        Returns:
            Dictionary: block_id -> hash (hex)
        """
        return self.get_all_hashes()

    def import_hashes(self, hashes: Dict[int, str]):
        """
        Import hashes (from blockchain or file).
        
        Args:
            hashes: Dictionary mapping block_id -> hash
        """
        for block_id, hash_hex in hashes.items():
            if block_id not in self.block_hashes:
                # Create BlockHash without size info (can be None)
                self.block_hashes[block_id] = BlockHash(
                    block_id=block_id,
                    hash=hash_hex,
                    plaintext_size=0
                )
