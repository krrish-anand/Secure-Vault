"""
Network Transmitter Module

Sends encrypted blocks over TCP with retry logic and checksums.
Protocol: [Header(4B sequence)] [Block Data] [Checksum(4B CRC32)]
"""

import socket
import struct
import time
import json
from typing import Optional, Dict, List, Tuple
from transmission.block_manager import EncryptedBlock, BlockState
import zlib  # For CRC32 checksums


class BlockTransmitter:
    """
    Transmits encrypted blocks over TCP connection.
    Handles retries, timeouts, and checksum verification.
    """

    def __init__(self, max_retries: int = 3, timeout: float = 5.0, buffer_size: int = 65536):
        """
        Initialize block transmitter.
        
        Args:
            max_retries: Maximum transmission attempts per block
            timeout: Socket timeout in seconds
            buffer_size: TCP send/receive buffer size
        """
        self.max_retries = max_retries
        self.timeout = timeout
        self.buffer_size = buffer_size
        self.socket = None
        self.transmission_stats = {
            "blocks_sent": 0,
            "blocks_failed": 0,
            "total_bytes_sent": 0,
            "total_attempts": 0,
            "avg_time_per_block_ms": 0
        }
        self.transmission_times = []

    def connect(self, host: str, port: int) -> bool:
        """
        Connect to remote receiver.
        
        Args:
            host: Remote host address
            port: Remote port number
            
        Returns:
            True if connected, False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((host, port))
            print(f"✓ Connected to {host}:{port}")
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False

    def is_connected(self) -> bool:
        """Check if transmitter is connected."""
        return self.socket is not None

    def close(self) -> None:
        """Close connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate CRC32 checksum for data.
        
        Args:
            data: Data to checksum
            
        Returns:
            CRC32 checksum as integer
        """
        return zlib.crc32(data) & 0xffffffff

    def _send_block_raw(self, sequence: int, block_data: bytes) -> bool:
        """
        Send block with protocol: [Header(4B seq, 4B size)] [Data] [Checksum(4B)]
        
        Args:
            sequence: Sequence number
            block_data: Block encrypted data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create header with sequence number and block size
            header = struct.pack(">II", sequence, len(block_data))
            
            # Calculate checksum
            checksum = self._calculate_checksum(block_data)
            checksum_bytes = struct.pack(">I", checksum)
            
            # Send header + data + checksum
            packet = header + block_data + checksum_bytes
            
            self.socket.sendall(packet)
            return True
            
        except Exception as e:
            print(f"✗ Failed to send block {sequence}: {e}")
            return False

    def send_block(self, block: EncryptedBlock) -> bool:
        """
        Send block with retry logic.
        
        Args:
            block: EncryptedBlock to send
            
        Returns:
            True if sent successfully, False if max retries exceeded
        """
        if not self.is_connected():
            print("✗ Not connected to receiver")
            return False
        
        start_time = time.time()
        
        # Retry loop
        for attempt in range(self.max_retries):
            self.transmission_stats["total_attempts"] += 1
            
            if self._send_block_raw(block.block_id, block.encrypted_data):
                elapsed_ms = (time.time() - start_time) * 1000
                self.transmission_times.append(elapsed_ms)
                self.transmission_stats["blocks_sent"] += 1
                self.transmission_stats["total_bytes_sent"] += len(block.encrypted_data)
                
                # Update average time
                if self.transmission_times:
                    avg_time = sum(self.transmission_times) / len(self.transmission_times)
                    self.transmission_stats["avg_time_per_block_ms"] = avg_time
                
                print(f"✓ Block {block.block_id} sent ({len(block.encrypted_data)} bytes, attempt {attempt+1})")
                return True
            
            # Retry delay
            if attempt < self.max_retries - 1:
                wait_time = 0.5 * (2 ** attempt)  # Exponential backoff: 0.5s, 1s, 2s
                print(f"  Retrying block {block.block_id} in {wait_time:.1f}s...")
                time.sleep(wait_time)
        
        # All retries failed
        self.transmission_stats["blocks_failed"] += 1
        print(f"✗ Block {block.block_id} failed after {self.max_retries} attempts")
        return False

    def send_blocks(self, blocks: List[EncryptedBlock]) -> Tuple[int, int]:
        """
        Send multiple blocks.
        
        Args:
            blocks: List of EncryptedBlocks to send
            
        Returns:
            Tuple of (successful_count, failed_count)
        """
        successful = 0
        failed = 0
        
        for block in blocks:
            if self.send_block(block):
                successful += 1
            else:
                failed += 1
        
        return successful, failed

    def confirm_receipt(self, block_id: int) -> bool:
        """
        Wait for receiver confirmation of block receipt.
        
        Args:
            block_id: Block ID to confirm
            
        Returns:
            True if confirmed, False on timeout
        """
        try:
            # Receive confirmation (sender expects 1 byte per block)
            response = self.socket.recv(1)
            if response:
                return True
        except socket.timeout:
            pass
        except Exception as e:
            print(f"✗ Confirmation error: {e}")
        
        return False

    def get_transmission_stats(self) -> Dict:
        """Get transmission statistics."""
        return self.transmission_stats.copy()

    def get_summary(self) -> str:
        """Get human-readable transmission summary."""
        stats = self.transmission_stats
        return (
            f"Blocks sent: {stats['blocks_sent']} | "
            f"Failed: {stats['blocks_failed']} | "
            f"Bytes: {stats['total_bytes_sent']} | "
            f"Avg time: {stats['avg_time_per_block_ms']:.2f}ms"
        )

    def reset_stats(self):
        """Reset transmission statistics."""
        self.transmission_stats = {
            "blocks_sent": 0,
            "blocks_failed": 0,
            "total_bytes_sent": 0,
            "total_attempts": 0,
            "avg_time_per_block_ms": 0
        }
        self.transmission_times.clear()
