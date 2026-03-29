"""
Block Manager Module

Manages the lifecycle of encrypted blocks.
Tracks: encryption state, metadata, hashes, and transmission status.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List
from enum import Enum
from transmission.block_splitter import BlockMetadata


class BlockState(Enum):
    """States a block can be in during lifecycle."""
    CREATED = "created"           # Block metadata created
    ENCRYPTED = "encrypted"       # Block encrypted
    HASHED = "hashed"             # Block hash computed
    REGISTERED = "registered"     # Hash registered in blockchain
    TRANSMITTED = "transmitted"   # Block sent over network
    RECEIVED = "received"         # Block received on remote side
    VERIFIED = "verified"         # Block hash verified against blockchain
    RECONSTRUCTED = "reconstructed"  # Block used in file reconstruction


@dataclass
class EncryptedBlock:
    """Represents an encrypted block with full metadata."""
    
    # Block identification
    block_id: int
    
    # Erasure coding info
    block_type: str = "data"      # "data" or "parity"
    group_id: int = 0             # Group for XOR recovery
    
    # Original block metadata
    original_metadata: BlockMetadata = None
    
    # Encryption information
    plaintext_size: int = 0       # Original unencrypted size
    encrypted_data: bytes = b""   # Encrypted block content
    encrypted_size: int = 0       # Size after encryption
    encryption_method: str = ""   # "AES-128" or "AES-256"
    
    # Hashing & verification
    plaintext_hash: str = ""      # SHA-256 of plaintext
    encrypted_hash: Optional[str] = None  # SHA-256 of encrypted data
    
    # Blockchain
    tx_id: Optional[str] = None   # Transaction ID in blockchain
    
    # Transmission & state
    state: BlockState = field(default=BlockState.CREATED)
    transmission_attempts: int = field(default=0)
    last_error: Optional[str] = field(default=None)
    
    # Metadata
    created_timestamp: float = field(default_factory=lambda: __import__('time').time())


class BlockManager:
    """
    Manages collection of encrypted blocks.
    Tracks states, coordinates transmission, handles recovery.
    """

    def __init__(self):
        """Initialize block manager."""
        self.blocks: Dict[int, EncryptedBlock] = {}
        self.total_file_size = 0
        self.total_plaintext_size = 0
        self.total_encrypted_size = 0
        self.block_sequence = []  # Ordered list of block IDs

    def add_block(self, encrypted_block: EncryptedBlock) -> None:
        """
        Add encrypted block to manager.
        
        Args:
            encrypted_block: EncryptedBlock object
        """
        block_id = encrypted_block.block_id
        self.blocks[block_id] = encrypted_block
        
        # Update statistics
        self.total_plaintext_size += encrypted_block.plaintext_size
        self.total_encrypted_size += encrypted_block.encrypted_size
        
        # Track sequence
        if block_id not in self.block_sequence:
            self.block_sequence.append(block_id)
        
        self.block_sequence.sort()  # Keep sorted

    def get_block(self, block_id: int) -> Optional[EncryptedBlock]:
        """Get block by ID."""
        return self.blocks.get(block_id)

    def get_all_blocks(self) -> List[EncryptedBlock]:
        """Get all blocks in sequence order."""
        return [self.blocks[bid] for bid in self.block_sequence if bid in self.blocks]

    def update_block_state(self, block_id: int, new_state: BlockState) -> bool:
        """
        Update block state.
        
        Args:
            block_id: Block identifier
            new_state: New BlockState value
            
        Returns:
            True if updated, False if block not found
        """
        if block_id in self.blocks:
            self.blocks[block_id].state = new_state
            return True
        return False

    def get_block_state(self, block_id: int) -> Optional[BlockState]:
        """Get current state of block."""
        if block_id in self.blocks:
            return self.blocks[block_id].state
        return None

    def set_block_error(self, block_id: int, error: str) -> bool:
        """
        Set error message for block.
        
        Args:
            block_id: Block identifier
            error: Error description
            
        Returns:
            True if set, False if block not found
        """
        if block_id in self.blocks:
            self.blocks[block_id].last_error = error
            return True
        return False

    def increment_transmission_attempts(self, block_id: int) -> bool:
        """
        Increment transmission attempt counter.
        
        Args:
            block_id: Block identifier
            
        Returns:
            True if incremented, False if block not found
        """
        if block_id in self.blocks:
            self.blocks[block_id].transmission_attempts += 1
            return True
        return False

    def get_blocks_by_state(self, state: BlockState) -> List[EncryptedBlock]:
        """
        Get all blocks in a specific state.
        
        Args:
            state: BlockState to filter by
            
        Returns:
            List of matching blocks
        """
        return [b for b in self.blocks.values() if b.state == state]

    def get_unverified_blocks(self) -> List[int]:
        """Get block IDs that haven't been verified yet."""
        # Blocks are unverified if they haven't reached verification state
        verified_states = {BlockState.VERIFIED, BlockState.RECONSTRUCTED}
        return [b.block_id for b in self.blocks.values() 
                if b.state not in verified_states]

    def get_untransmitted_blocks(self) -> List[int]:
        """Get block IDs that haven't been transmitted yet."""
        # Blocks are untransmitted if they're in early-stage states only
        untransmitted_states = {
            BlockState.CREATED, 
            BlockState.ENCRYPTED, 
            BlockState.HASHED, 
            BlockState.REGISTERED
        }
        return [b.block_id for b in self.blocks.values() 
                if b.state in untransmitted_states]

    def mark_transmitted(self, block_id: int) -> bool:
        """Mark block as transmitted."""
        return self.update_block_state(block_id, BlockState.TRANSMITTED)

    def mark_received(self, block_id: int) -> bool:
        """Mark block as received."""
        return self.update_block_state(block_id, BlockState.RECEIVED)

    def mark_verified(self, block_id: int) -> bool:
        """Mark block as verified."""
        return self.update_block_state(block_id, BlockState.VERIFIED)

    def get_block_count(self) -> int:
        """Get total number of blocks."""
        return len(self.blocks)

    def get_statistics(self) -> dict:
        """
        Get detailed statistics about blocks.
        
        Returns:
            Dict with counts by state, sizes, etc.
        """
        state_counts = {}
        for state in BlockState:
            state_counts[state.value] = len(self.get_blocks_by_state(state))
        
        return {
            "total_blocks": len(self.blocks),
            "total_plaintext_size": self.total_plaintext_size,
            "total_encrypted_size": self.total_encrypted_size,
            "size_increase_percent": (
                ((self.total_encrypted_size - self.total_plaintext_size) / self.total_plaintext_size * 100)
                if self.total_plaintext_size > 0 else 0
            ),
            "blocks_by_state": state_counts,
            "avg_block_size": (
                self.total_plaintext_size // len(self.blocks)
                if len(self.blocks) > 0 else 0
            )
        }

    def get_summary(self) -> str:
        """Get human-readable manager summary."""
        stats = self.get_statistics()
        return (
            f"Blocks: {stats['total_blocks']} | "
            f"Plaintext: {stats['total_plaintext_size']} bytes | "
            f"Encrypted: {stats['total_encrypted_size']} bytes | "
            f"Increase: {stats['size_increase_percent']:.1f}%"
        )

    def validate_all_blocks(self) -> bool:
        """
        Validate all blocks exist and have required metadata.
        
        Returns:
            True if all blocks valid, False otherwise
        """
        if not self.blocks:
            return False
        
        for bid in self.block_sequence:
            if bid not in self.blocks:
                return False
            
            block = self.blocks[bid]
            # Check required fields
            if not block.encrypted_data or not block.plaintext_hash:
                return False
        
        return True

    def clear(self):
        """Clear all blocks (use with caution!)."""
        self.blocks.clear()
        self.block_sequence.clear()
        self.total_file_size = 0
        self.total_plaintext_size = 0
        self.total_encrypted_size = 0
