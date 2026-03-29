"""
Network Receiver Module

Receives encrypted blocks over TCP and validates checksums.
Protocol: [Header(4B sequence)] [Block Data] [Checksum(4B CRC32)]
Responds with confirmation byte per block received.
"""

import socket
import struct
import threading
import time
import errno
import json
from typing import Optional, Dict, Callable
from transmission.block_manager import EncryptedBlock, BlockMetadata, BlockState
import zlib  # For CRC32 checksums


class BlockReceiver:
    """
    Receives encrypted blocks over TCP.
    Validates checksums, stores blocks, and sends confirmations.
    """

    def __init__(self, port: int, buffer_size: int = 65536, timeout: float = 30.0):
        """
        Initialize block receiver.
        
        Args:
            port: Port to listen on
            buffer_size: TCP receive buffer size
            timeout: Socket timeout in seconds
        """
        self.port = port
        self.buffer_size = buffer_size
        self.timeout = timeout
        self.server_socket = None
        self.client_socket = None
        self.is_listening = False
        self.received_blocks: Dict[int, bytes] = {}
        self.block_count = 0
        self.expected_blocks = 0
        self.reception_stats = {
            "blocks_received": 0,
            "blocks_failed_checksum": 0,
            "total_bytes_received": 0,
            "total_attempts": 0
        }

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate CRC32 checksum for data.
        
        Args:
            data: Data to checksum
            
        Returns:
            CRC32 checksum as integer
        """
        return zlib.crc32(data) & 0xffffffff

    def listen(self) -> bool:
        """
        Begin listening for connections.
        
        Returns:
            True if listening started, False otherwise
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(1)
            self.is_listening = True
            print(f"✓ Listening on port {self.port}")
            return True
        except Exception as e:
            print(f"✗ Failed to listen: {e}")
            return False

    def accept_connection(self) -> bool:
        """
        Accept incoming connection from transmitter.
        
        Returns:
            True if connection accepted, False otherwise
        """
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.client_socket.settimeout(self.timeout)
            print(f"✓ Accepted connection from {addr}")
            return True
        except Exception as e:
            print(f"✗ Failed to accept connection: {e}")
            return False

    def _receive_block_raw(self) -> Optional[tuple]:
        """
        Receive one block with protocol: [Header(4B seq, 4B size)] [Data] [Checksum(4B)]
        
        Returns:
            Tuple of (sequence, block_data) or None if failed
        """
        try:
            # Read header (8 bytes: sequence + size)
            header_data = self._recv_exactly(8)
            if not header_data:
                return None
            
            sequence, block_size = struct.unpack(">II", header_data)
            
            # Read block data (exact size)
            block_data = self._recv_exactly(block_size)
            if not block_data or len(block_data) != block_size:
                print(f"✗ Failed to receive full block data")
                return None
            
            # Read checksum (4 bytes)
            checksum_bytes = self._recv_exactly(4)
            if not checksum_bytes:
                print(f"✗ Failed to receive checksum")
                return None
            
            transmitted_checksum = struct.unpack(">I", checksum_bytes)[0]
            
            # Verify checksum
            calculated_checksum = self._calculate_checksum(block_data)
            if calculated_checksum != transmitted_checksum:
                self.reception_stats["blocks_failed_checksum"] += 1
                print(f"✗ Checksum mismatch on block {sequence}")
                return None
            
            return (sequence, block_data)
            
        except socket.timeout:
            # Timeout is normal - just means no more blocks coming
            return None
        except OSError as e:
            # Connection reset by peer (10054) is normal when sender closes
            if e.errno == 10054 or e.errno == 104:  # WSAECONNRESET or ECONNRESET
                return None
            print(f"✗ Failed to receive block: {e}")
            return None
        except Exception as e:
            print(f"✗ Failed to receive block: {e}")
            return None
    
    def _recv_exactly(self, num_bytes: int) -> Optional[bytes]:
        """
        Receive exactly num_bytes from socket.
        Handles TCP fragmentation by looping until all bytes received.
        
        Args:
            num_bytes: Number of bytes to receive
            
        Returns:
            Bytes received or None if failed
        """
        data = b""
        while len(data) < num_bytes:
            try:
                chunk = self.client_socket.recv(num_bytes - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                # Timeout is normal
                return None
            except OSError as e:
                # Connection reset is normal when sender closes gracefully
                if e.errno in (errno.ECONNRESET, 10054):  # ECONNRESET or Windows WSAECONNRESET
                    return None
                raise
        return data

    def receive_block(self) -> Optional[tuple]:
        """
        Receive a block and send confirmation.
        
        Returns:
            Tuple of (block_id, block_data) or None if failed
        """
        if not self.client_socket:
            print("✗ Not connected")
            return None
        
        self.reception_stats["total_attempts"] += 1
        
        result = self._receive_block_raw()
        if result:
            sequence, block_data = result
            self.received_blocks[sequence] = block_data
            self.reception_stats["blocks_received"] += 1
            self.reception_stats["total_bytes_received"] += len(block_data)
            self.block_count += 1
            
            # Send confirmation
            try:
                self.client_socket.send(b'\x01')  # Confirmation byte
            except Exception as e:
                print(f"✗ Failed to send confirmation: {e}")
            
            print(f"✓ Block {sequence} received ({len(block_data)} bytes)")
            return (sequence, block_data)
        
        return None

    def receive_all_blocks(self, expected_count: int) -> bool:
        """
        Receive all expected blocks.
        
        Args:
            expected_count: Number of blocks to receive
            
        Returns:
            True if all blocks received, False otherwise
        """
        self.expected_blocks = expected_count
        successful = 0
        
        while self.block_count < expected_count:
            result = self.receive_block()
            if result:
                successful += 1
            else:
                # Timeout or error
                break
        
        print(f"Received {successful}/{expected_count} blocks")
        return successful == expected_count

    def get_received_blocks(self) -> Dict[int, bytes]:
        """Get all received blocks."""
        return self.received_blocks.copy()

    def get_block_data(self, block_id: int) -> Optional[bytes]:
        """Get received block data by ID."""
        return self.received_blocks.get(block_id)

    def is_block_received(self, block_id: int) -> bool:
        """Check if block was received."""
        return block_id in self.received_blocks

    def get_missing_blocks(self, total_blocks: int) -> list:
        """
        Get list of missing block IDs.
        
        Args:
            total_blocks: Total number of expected blocks
            
        Returns:
            List of missing block IDs
        """
        expected_ids = set(range(total_blocks))
        received_ids = set(self.received_blocks.keys())
        missing = sorted(expected_ids - received_ids)
        return missing

    def get_reception_stats(self) -> Dict:
        """Get reception statistics."""
        return self.reception_stats.copy()

    def get_summary(self) -> str:
        """Get human-readable reception summary."""
        stats = self.reception_stats
        return (
            f"Blocks received: {stats['blocks_received']} | "
            f"Failed checksums: {stats['blocks_failed_checksum']} | "
            f"Bytes: {stats['total_bytes_received']}"
        )

    def close(self) -> None:
        """Close receiver sockets."""
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        
        self.is_listening = False

    def reset(self):
        """Reset receiver state."""
        self.received_blocks.clear()
        self.block_count = 0
        self.expected_blocks = 0
        self.reception_stats = {
            "blocks_received": 0,
            "blocks_failed_checksum": 0,
            "total_bytes_received": 0,
            "total_attempts": 0
        }
