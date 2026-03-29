"""
Erasure Coding Module

Implements XOR-based erasure coding for self-healing file transmission.
Allows recovery of up to 1 missing block per group (for every 2 data blocks).

How it works:
  - For blocks [0,1] → parity = block[0] XOR block[1]
  - If block[0] missing: block[0] = block[1] XOR parity
  - If block[1] missing: block[1] = block[0] XOR parity
  
Group logic:
  - Blocks 0,1 in group 0, parity in group 0
  - Blocks 2,3 in group 1, parity in group 1
  - Blocks 4,5 in group 2, parity in group 2
  - etc.

Padding:
  - Blocks with different lengths are padded to max length for XOR operations
  - Original sizes stored to remove padding during recovery
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import json


def pad_block(block: bytes, target_length: int) -> bytes:
    """
    Pad a block with zeros to target length.
    
    Args:
        block: Block data
        target_length: Target length in bytes
        
    Returns:
        Padded block
    """
    if len(block) >= target_length:
        return block
    return block + bytes(target_length - len(block))


def unpad_block(block: bytes, original_length: int) -> bytes:
    """
    Remove padding from a block to restore original length.
    
    Args:
        block: Padded block data
        original_length: Original length before padding
        
    Returns:
        Unpadded block (truncated to original length)
    """
    return block[:original_length]


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """
    XOR two byte arrays of equal length.
    
    Args:
        b1: First byte array
        b2: Second byte array
        
    Returns:
        XORed result
        
    Raises:
        ValueError: If lengths don't match
    """
    if len(b1) != len(b2):
        raise ValueError(f"Byte arrays must be equal length: {len(b1)} vs {len(b2)}")
    
    return bytes(a ^ b for a, b in zip(b1, b2))


def generate_parity_blocks(blocks: List[bytes]) -> Tuple[List[Tuple[int, bytes]], Dict[int, int]]:
    """
    Generate parity blocks from data blocks using XOR.
    
    For every 2 consecutive blocks, generates 1 parity block:
    - Blocks [0,1] → parity at index 0 (group 0)
    - Blocks [2,3] → parity at index 1 (group 1)
    - etc.
    
    If odd number of blocks, last block is alone in its group
    (no parity generated for it).
    
    Handles variable-length blocks by padding to max length before XOR.
    
    Args:
        blocks: List of data blocks (bytes)
        
    Returns:
        Tuple of:
        - List of (parity_index, parity_data) tuples
          Example: [(0, parity_01), (1, parity_23), ...]
        - Dict of {block_id: original_length} for all blocks
    """
    parity_blocks = []
    block_sizes = {}
    
    # Store original block sizes
    for block_id, block in enumerate(blocks):
        block_sizes[block_id] = len(block)
    
    # Find max block size for padding
    max_block_size = max(len(b) for b in blocks) if blocks else 0
    
    for i in range(0, len(blocks) - 1, 2):
        block0 = blocks[i]
        block1 = blocks[i + 1]
        
        # Pad blocks to equal length
        block0_padded = pad_block(block0, max_block_size)
        block1_padded = pad_block(block1, max_block_size)
        
        # XOR the two padded blocks to create parity
        parity = xor_bytes(block0_padded, block1_padded)
        
        # Parity index = which group (0, 1, 2, ...)
        parity_index = i // 2
        parity_blocks.append((parity_index, parity))
    
    return parity_blocks, block_sizes


def recover_block(surviving_block: bytes, parity: bytes) -> bytes:
    """
    Recover a missing block from a surviving block and parity.
    
    Properties:
    - block0 XOR block1 = parity
    - Therefore: block0 = block1 XOR parity
    - And: block1 = block0 XOR parity
    
    Args:
        surviving_block: The block that was not lost
        parity: The parity block for the group
        
    Returns:
        The recovered block
    """
    return xor_bytes(surviving_block, parity)


def recover_missing_blocks(
    received_blocks: Dict[int, bytes],
    parity_blocks: Dict[int, bytes],
    total_data_blocks: int,
    block_sizes: Dict[int, int] = None
) -> Dict[int, bytes]:
    """
    Recover missing data blocks using parity blocks.
    
    Each group can recover AT MOST 1 missing block.
    Group i contains data blocks [2i, 2i+1].
    
    Args:
        received_blocks: Dict {block_id: block_data} of received blocks
        parity_blocks: Dict {group_id: parity_data} of parity blocks
        total_data_blocks: Original number of data blocks
        block_sizes: Dict {block_id: original_length} for unpadding recovered blocks
        
    Returns:
        Dict of recovered blocks {block_id: block_data}
        
    Example:
        received = {0: data0_bytes, 2: data2_bytes}  # Lost block 1
        parity = {0: parity0_bytes, 1: parity1_bytes}
        total = 4
        
        Result:
        {1: recovered_block1, 3: recovered_block3}
    """
    recovered = {}
    
    # Process each group
    for group_id in range((total_data_blocks + 1) // 2):
        block_id_0 = group_id * 2
        block_id_1 = group_id * 2 + 1
        
        # Skip if group parity is not available
        if group_id not in parity_blocks:
            continue
        
        parity = parity_blocks[group_id]
        
        # Count how many blocks in this group are missing
        has_0 = block_id_0 in received_blocks
        has_1 = block_id_1 in received_blocks and block_id_1 < total_data_blocks
        
        missing_count = sum([not has_0, not has_1])
        
        if missing_count == 0:
            # Both present or one doesn't exist - no recovery needed
            continue
        elif missing_count == 1:
            # Can recover exactly 1 missing block
            if not has_0:
                # Recover block 0
                recovered_data = recover_block(received_blocks[block_id_1], parity)
                # Unpad if original size metadata available
                if block_sizes and block_id_0 in block_sizes:
                    recovered_data = unpad_block(recovered_data, block_sizes[block_id_0])
                recovered[block_id_0] = recovered_data
            elif block_id_1 < total_data_blocks and not has_1:
                # Recover block 1
                recovered_data = recover_block(received_blocks[block_id_0], parity)
                # Unpad if original size metadata available
                if block_sizes and block_id_1 in block_sizes:
                    recovered_data = unpad_block(recovered_data, block_sizes[block_id_1])
                recovered[block_id_1] = recovered_data
        else:
            # 2 missing blocks in same group - cannot recover
            pass
    
    return recovered


@dataclass
class BlockWithMetadata:
    """Enhanced block metadata including type and group info."""
    block_id: int
    block_type: str  # "data" or "parity"
    group_id: int    # Which group this block belongs to
    data: bytes      # Actual block data
    
    def __repr__(self) -> str:
        return f"Block(id={self.block_id}, type={self.block_type}, group={self.group_id}, size={len(self.data)})"
