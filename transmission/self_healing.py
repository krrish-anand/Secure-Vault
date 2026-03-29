"""
Self-Healing Module

Detects missing blocks and implements recovery strategies.

Recovery Strategies:
1. Request retransmission of missing blocks only (not full file)
2. Error-correcting codes (future enhancement)
3. Automatic reassembly when sufficient blocks received
"""

from typing import List, Dict, Optional, Tuple
from transmission.block_manager import BlockManager, BlockState


class MissingBlockDetector:
    """
    Detects which blocks are missing from a transmission.
    Compares expected vs. received blocks and identifies gaps.
    """

    def __init__(self):
        """Initialize detector."""
        self.expected_block_count = 0
        self.received_block_ids = set()
        self.missing_block_ids = set()

    def set_expected_blocks(self, block_count: int):
        """
        Set the expected number of blocks for file.
        
        Args:
            block_count: Total number of expected blocks
        """
        self.expected_block_count = block_count
        self._update_missing()

    def mark_block_received(self, block_id: int):
        """
        Mark a block as received.
        
        Args:
            block_id: Block identifier
        """
        self.received_block_ids.add(block_id)
        self._update_missing()

    def mark_blocks_received(self, block_ids: List[int]):
        """
        Mark multiple blocks as received.
        
        Args:
            block_ids: List of block identifiers
        """
        self.received_block_ids.update(block_ids)
        self._update_missing()

    def _update_missing(self):
        """Update missing blocks list based on expected vs. received."""
        expected = set(range(self.expected_block_count))
        self.missing_block_ids = expected - self.received_block_ids

    def detect_missing_blocks(self) -> List[int]:
        """
        Get list of missing block IDs.
        
        Returns:
            Sorted list of missing block IDs
        """
        return sorted(self.missing_block_ids)

    def get_missing_count(self) -> int:
        """Get count of missing blocks."""
        return len(self.missing_block_ids)

    def is_complete(self) -> bool:
        """Check if all blocks received."""
        return len(self.missing_block_ids) == 0

    def get_completion_percentage(self) -> float:
        """
        Get percentage of blocks received.
        
        Returns:
            Percentage (0-100)
        """
        if self.expected_block_count == 0:
            return 0.0
        
        received_count = len(self.received_block_ids)
        return (received_count / self.expected_block_count) * 100

    def reset(self):
        """Reset detector."""
        self.expected_block_count = 0
        self.received_block_ids.clear()
        self.missing_block_ids.clear()

    def get_summary(self) -> str:
        """Get summary of detection status."""
        return (
            f"Expected: {self.expected_block_count}, "
            f"Received: {len(self.received_block_ids)}, "
            f"Missing: {len(self.missing_block_ids)}, "
            f"Progress: {self.get_completion_percentage():.1f}%"
        )


class BlockReassembler:
    """
    Reassembles file from received blocks.
    Validates block sequence, handles reconstruction with missing blocks.
    """

    def __init__(self, block_manager: BlockManager):
        """
        Initialize reassembler.
        
        Args:
            block_manager: BlockManager containing encrypted blocks
        """
        self.block_manager = block_manager
        self.reassembled_data = b""
        self.reconstruction_attempts = 0

    def reassemble_file(self, received_block_data: Dict[int, bytes],
                       allow_gaps: bool = False) -> Optional[bytes]:
        """
        Reassemble file from received block data.
        
        Args:
            received_block_data: Dict mapping block_id -> block_data
            allow_gaps: If True, reassemble even with missing blocks (won't work)
            
        Returns:
            Reassembled file data or None if failed
        """
        self.reconstruction_attempts += 1
        
        if not received_block_data:
            print("✗ No blocks to reassemble")
            return None
        
        try:
            # Get expected block count
            max_block_id = max(received_block_data.keys())
            expected_block_count = max_block_id + 1
            
            # Check for missing blocks
            expected_ids = set(range(expected_block_count))
            received_ids = set(received_block_data.keys())
            missing_ids = expected_ids - received_ids
            
            if missing_ids:
                if allow_gaps:
                    print(f"⚠ Warning: {len(missing_ids)} blocks are missing, "
                          f"file might be incomplete or corrupted")
                else:
                    print(f"✗ Cannot reassemble: {len(missing_ids)} missing blocks: {sorted(missing_ids)}")
                    return None
            
            # Reassemble in order
            self.reassembled_data = b""
            
            for block_id in range(expected_block_count):
                if block_id in received_block_data:
                    self.reassembled_data += received_block_data[block_id]
                else:
                    print(f"✗ Missing block {block_id}")
                    if not allow_gaps:
                        return None
            
            print(f"✓ File reassembled: {len(self.reassembled_data)} bytes "
                  f"from {len(received_ids)} blocks")
            return self.reassembled_data
            
        except Exception as e:
            print(f"✗ Reassembly failed: {e}")
            return None

    def validate_file_integrity(self, reassembled_data: bytes,
                               expected_hash: Optional[str] = None) -> bool:
        """
        Validate reassembled file integrity.
        
        Args:
            reassembled_data: File data to validate
            expected_hash: Optional SHA-256 hash of original file
            
        Returns:
            True if valid, False otherwise
        """
        import hashlib
        
        if not reassembled_data:
            print("✗ No data to validate")
            return False
        
        # Compute hash of reassembled data
        computed_hash = hashlib.sha256(reassembled_data).hexdigest()
        
        if expected_hash:
            if computed_hash == expected_hash:
                print(f"✓ File integrity verified (hash matches)")
                return True
            else:
                print(f"✗ File integrity check failed (hash mismatch)")
                print(f"  Expected: {expected_hash}")
                print(f"  Got:      {computed_hash}")
                return False
        else:
            print(f"✓ File hash computed: {computed_hash[:16]}...")
            return True

    def get_reassembled_data(self) -> bytes:
        """Get reassembled file data."""
        return self.reassembled_data

    def get_summary(self) -> str:
        """Get reassembly summary."""
        return (
            f"Reassembly attempts: {self.reconstruction_attempts}, "
            f"Data size: {len(self.reassembled_data)} bytes"
        )


class SelfHealingSystem:
    """
    Orchestrates missing block detection and recovery.
    Implements retry logic and recovery strategies.
    """

    def __init__(self, block_manager: BlockManager, max_recovery_attempts: int = 3):
        """
        Initialize self-healing system.
        
        Args:
            block_manager: BlockManager instance
            max_recovery_attempts: Max attempts to recover missing blocks
        """
        self.block_manager = block_manager
        self.max_recovery_attempts = max_recovery_attempts
        self.detector = MissingBlockDetector()
        self.reassembler = BlockReassembler(block_manager)
        self.recovery_attempts = 0

    def detect_missing_blocks(self, total_blocks: int, received_ids: List[int]) -> List[int]:
        """
        Detect missing blocks.
        
        Args:
            total_blocks: Expected total block count
            received_ids: List of received block IDs
            
        Returns:
            List of missing block IDs
        """
        self.detector.set_expected_blocks(total_blocks)
        self.detector.mark_blocks_received(received_ids)
        missing = self.detector.detect_missing_blocks()
        
        if missing:
            print(f"⚠ {len(missing)} missing blocks detected: {missing}")
        else:
            print(f"✓ All {total_blocks} blocks received successfully")
        
        return missing

    def attempt_recovery(self, received_block_data: Dict[int, bytes]) -> Tuple[bool, Optional[bytes]]:
        """
        Attempt to recover missing blocks and reassemble file.
        
        Args:
            received_block_data: Dict of received block_id -> data
            
        Returns:
            Tuple of (success, reassembled_data)
        """
        print(f"\n[Recovery Attempt {self.recovery_attempts + 1}/{self.max_recovery_attempts}]")
        
        # Strategy 1: Try to reassemble with allow_gaps=True (will fail if blocks missing)
        reassembled = self.reassembler.reassemble_file(
            received_block_data,
            allow_gaps=False  # Strict - fail if any missing
        )
        
        if reassembled:
            print("✓ Recovery successful")
            return True, reassembled
        
        self.recovery_attempts += 1
        
        if self.recovery_attempts >= self.max_recovery_attempts:
            print(f"✗ Recovery failed after {self.max_recovery_attempts} attempts")
            return False, None
        
        # Strategy 2: Request retransmission of missing blocks
        missing = self.detector.detect_missing_blocks()
        if missing:
            print(f"→ Request retransmission of {len(missing)} blocks: {missing}")
            # In real implementation, would request transmitter to resend
            # For now, just report what would be requested
            return False, None
        
        return False, None

    def get_recovery_status(self) -> dict:
        """Get current recovery status."""
        return {
            "detector": self.detector.get_summary(),
            "reassembler": self.reassembler.get_summary(),
            "recovery_attempts": self.recovery_attempts,
            "max_attempts": self.max_recovery_attempts
        }

    def reset(self):
        """Reset recovery system."""
        self.detector.reset()
        self.reassembler = BlockReassembler(self.block_manager)
        self.recovery_attempts = 0
