"""
Block Splitter Module

Splits large files into smaller blocks for transmission.
Each block has metadata (id, sequence, size, offset).
"""

import os
from dataclasses import dataclass
from typing import List, Tuple, Optional


@dataclass
class BlockMetadata:
    """Metadata for a single block."""
    block_id: int              # Unique block identifier (0, 1, 2, ...)
    sequence: int              # Sequence number in transmission order
    size: int                  # Size of block data in bytes
    offset: int                # Offset in original file
    plaintext_size: int        # Unencrypted data size (may differ after encryption)
    hash: Optional[str] = None # SHA-256 hash (filled later by BlockHasher)


class BlockSplitter:
    """
    Splits a file into fixed-size blocks.
    Tracks metadata for each block: id, offset, size, sequence.
    """

    def __init__(self, block_size: int = 65536):
        """
        Initialize block splitter.
        
        Args:
            block_size: Size of each block in bytes (default: 64KB)
        """
        self.block_size = block_size
        self.blocks = []
        self.total_file_size = 0
        self.block_count = 0

    def split_file(self, file_path: str) -> List[BlockMetadata]:
        """
        Split a file into blocks and return Block metadata list.
        
        Args:
            file_path: Path to file to split
            
        Returns:
            List of BlockMetadata objects
            
        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Get file size
        self.total_file_size = os.path.getsize(file_path)
        self.blocks = []
        block_id = 0
        offset = 0
        
        with open(file_path, 'rb') as f:
            while offset < self.total_file_size:
                # Read up to block_size bytes
                data = f.read(self.block_size)
                block_data_size = len(data)
                
                if block_data_size == 0:
                    break
                
                # Create block metadata
                block = BlockMetadata(
                    block_id=block_id,
                    sequence=block_id,
                    size=block_data_size,
                    offset=offset,
                    plaintext_size=block_data_size,
                    hash=None  # Will be set by BlockHasher
                )
                
                self.blocks.append(block)
                offset += block_data_size
                block_id += 1
        
        self.block_count = len(self.blocks)
        return self.blocks

    def get_blocks(self) -> List[BlockMetadata]:
        """
        Get list of all block metadata (after split_file).
        
        Returns:
            List of BlockMetadata objects
        """
        return self.blocks

    def get_block_count(self) -> int:
        """Get total number of blocks."""
        return self.block_count

    def get_total_file_size(self) -> int:
        """Get original file size."""
        return self.total_file_size

    def get_block_by_id(self, block_id: int) -> Optional[BlockMetadata]:
        """
        Get block metadata by block ID.
        
        Args:
            block_id: Block identifier
            
        Returns:
            BlockMetadata if found, None otherwise
        """
        for block in self.blocks:
            if block.block_id == block_id:
                return block
        return None

    def read_block_data(self, file_path: str, block: BlockMetadata) -> bytes:
        """
        Read block data from file.
        
        Args:
            file_path: Path to file
            block: BlockMetadata object describing block location
            
        Returns:
            Block data as bytes
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            f.seek(block.offset)
            data = f.read(block.size)
        
        if len(data) != block.size:
            raise IOError(f"Failed to read complete block {block.block_id}")
        
        return data

    def validate_block_structure(self) -> bool:
        """
        Validate that blocks form a complete, contiguous file.
        
        Returns:
            True if all blocks are valid and contiguous
        """
        if not self.blocks:
            return False
        
        expected_offset = 0
        for i, block in enumerate(self.blocks):
            # Check block ID matches sequence
            if block.block_id != i:
                return False
            
            # Check sequence is correct
            if block.sequence != i:
                return False
            
            # Check blocks are contiguous
            if block.offset != expected_offset:
                return False
            
            expected_offset += block.size
        
        # Final offset should match total file size
        return expected_offset == self.total_file_size

    def get_missing_blocks(self, received_block_ids: List[int]) -> List[int]:
        """
        Find missing block IDs given a list of received blocks.
        
        Args:
            received_block_ids: List of block IDs that were received
            
        Returns:
            List of missing block IDs
        """
        received_set = set(received_block_ids)
        missing = []
        
        for block in self.blocks:
            if block.block_id not in received_set:
                missing.append(block.block_id)
        
        return missing

    def reset(self):
        """Clear all block metadata."""
        self.blocks = []
        self.total_file_size = 0
        self.block_count = 0

    def get_summary(self) -> str:
        """Get human-readable summary of block structure."""
        return (
            f"Blocks: {self.block_count} | "
            f"Block Size: {self.block_size} bytes | "
            f"Total File Size: {self.total_file_size} bytes"
        )
