"""
Mock Blockchain Module

Implements a local, tamper-proof ledger for block hashes.
Persists hashes to JSON file (blockchain.ledger).
Provides verification against stored hashes.
"""

import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib


@dataclass
class BlockHashEntry:
    """Single entry in blockchain ledger."""
    tx_id: str              # Transaction ID (format: "tx_00001", etc.)
    block_id: int           # Block identifier
    hash: str               # SHA-256 hash of block
    timestamp: str          # ISO format timestamp
    sender: str             # Sender identifier/address
    status: str             # "pending" or "verified"
    previous_hash: Optional[str] = None  # Hash of previous entry (blockchain linkage)


class MockBlockchain:
    """
    Local blockchain ledger for storing and verifying block hashes.
    
    Features:
    - Persistent JSON file storage
    - Hash verification against stored values
    - Transaction ID tracking
    - Tamper detection (via previous_hash linkage)
    """

    LEDGER_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "blockchain", "blockchain.ledger")
    TX_ID_FORMAT = "tx_{:05d}"  # tx_00001, tx_00002, etc.

    def __init__(self, ledger_path: str = LEDGER_FILE):
        """
        Initialize blockchain ledger.
        
        Args:
            ledger_path: Path to ledger JSON file
        """
        self.ledger_path = ledger_path
        self.ledger: Dict[str, Dict] = {}
        self.tx_counter = 0
        self.last_hash = None
        
        # Load or create ledger file
        self._load_ledger()

    def _load_ledger(self):
        """Load ledger from disk if it exists."""
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, 'r') as f:
                    data = json.load(f)
                    self.ledger = data.get("entries", {})
                    self.tx_counter = data.get("tx_counter", 0)
                    self.last_hash = data.get("last_hash", None)
            except Exception as e:
                print(f"Warning: Failed to load ledger: {e}. Starting fresh.")
                self.ledger = {}
                self.tx_counter = 0
                self.last_hash = None
        else:
            self.ledger = {}
            self.tx_counter = 0
            self.last_hash = None

    def _save_ledger(self):
        """Persist ledger to disk."""
        data = {
            "entries": self.ledger,
            "tx_counter": self.tx_counter,
            "last_hash": self.last_hash,
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.ledger_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error: Failed to save ledger: {e}")

    def add_hash(self, block_id: int, block_hash: str, sender: str = "system") -> str:
        """
        Add a block hash to the ledger.
        
        Args:
            block_id: Block identifier
            block_hash: SHA-256 hash of block
            sender: Identifier of sender (default: "system")
            
        Returns:
            Transaction ID assigned to this entry
        """
        # Generate transaction ID
        self.tx_counter += 1
        tx_id = self.TX_ID_FORMAT.format(self.tx_counter)
        
        # Compute hash of this transaction (includes previous hash for chain linkage)
        current_entry_data = f"{tx_id}{block_id}{block_hash}{sender}".encode()
        entry_hash = hashlib.sha256(current_entry_data).hexdigest()
        
        # Create entry
        entry = {
            "tx_id": tx_id,
            "block_id": block_id,
            "hash": block_hash,
            "timestamp": datetime.now().isoformat(),
            "sender": sender,
            "status": "verified",
            "previous_hash": self.last_hash,
            "entry_hash": entry_hash
        }
        
        # Store in ledger
        self.ledger[tx_id] = entry
        self.last_hash = entry_hash
        
        # Persist
        self._save_ledger()
        
        return tx_id

    def verify_hash(self, block_id: int, block_hash: str) -> bool:
        """
        Verify a block hash against the ledger.
        
        Args:
            block_id: Block identifier
            block_hash: SHA-256 hash to verify
            
        Returns:
            True if hash exists and matches in ledger
        """
        for tx_id, entry in self.ledger.items():
            if entry["block_id"] == block_id and entry["hash"] == block_hash:
                return True
        return False

    def get_hash(self, block_id: int) -> Optional[str]:
        """
        Get stored hash for a block.
        
        Args:
            block_id: Block identifier
            
        Returns:
            SHA-256 hash if found, None otherwise
        """
        for tx_id, entry in self.ledger.items():
            if entry["block_id"] == block_id:
                return entry["hash"]
        return None

    def get_entry(self, tx_id: str) -> Optional[Dict]:
        """
        Get ledger entry by transaction ID.
        
        Args:
            tx_id: Transaction ID
            
        Returns:
            Entry dict or None if not found
        """
        return self.ledger.get(tx_id)

    def is_valid(self) -> bool:
        """
        Verify blockchain integrity via hash chain.
        
        Returns:
            True if no tampering detected (all hashes chain correctly)
        """
        if not self.ledger:
            return True  # Empty chain is valid
        
        # Sort entries by transaction ID
        sorted_txs = sorted(self.ledger.keys())
        previous_hash = None
        
        for tx_id in sorted_txs:
            entry = self.ledger[tx_id]
            
            # Check chain linkage
            if entry.get("previous_hash") != previous_hash:
                return False
            
            # Recompute entry hash
            entry_data = f"{tx_id}{entry['block_id']}{entry['hash']}{entry['sender']}".encode()
            computed_hash = hashlib.sha256(entry_data).hexdigest()
            
            if entry.get("entry_hash") != computed_hash:
                return False
            
            previous_hash = entry.get("entry_hash")
        
        return True

    def get_chain(self) -> List[Dict]:
        """
        Get all ledger entries in order.
        
        Returns:
            List of entries sorted by transaction ID
        """
        sorted_txs = sorted(self.ledger.keys())
        return [self.ledger[tx_id] for tx_id in sorted_txs]

    def get_all_block_hashes(self) -> Dict[int, str]:
        """
        Export all block hashes from ledger.
        
        Returns:
            Dictionary: block_id -> hash
        """
        result = {}
        for tx_id, entry in self.ledger.items():
            block_id = entry["block_id"]
            result[block_id] = entry["hash"]
        return result

    def verify_block_against_ledger(self, block_id: int, block_hash: str) -> bool:
        """
        Verify a block hash against ledger entry.
        
        Args:
            block_id: Block identifier
            block_hash: SHA-256 hash to verify
            
        Returns:
            True if block hash matches ledger
        """
        return self.verify_hash(block_id, block_hash)

    def get_transaction_count(self) -> int:
        """Get total number of transactions in ledger."""
        return len(self.ledger)

    def get_summary(self) -> str:
        """Get human-readable ledger summary."""
        is_valid = self.is_valid()
        validity_status = "VALID" if is_valid else "TAMPERED"
        
        return (
            f"Blockchain Status: {validity_status} | "
            f"Transactions: {len(self.ledger)} | "
            f"Ledger File: {self.ledger_path}"
        )

    def clear(self):
        """Clear all entries and reset counter (use with caution!)."""
        self.ledger.clear()
        self.tx_counter = 0
        self.last_hash = None
        self._save_ledger()

    def export_ledger(self) -> Dict:
        """
        Export full ledger for backup/inspection.
        
        Returns:
            Ledger data dict
        """
        return {
            "entries": self.ledger,
            "tx_counter": self.tx_counter,
            "last_hash": self.last_hash,
            "is_valid": self.is_valid()
        }
    
    def import_ledger(self, ledger_data: Dict) -> bool:
        """
        Import ledger from another instance (e.g., from sender).
        Used by receiver to load the sender's blockchain for verification.
        
        Args:
            ledger_data: Ledger dict from export_ledger()
            
        Returns:
            True if import successful
        """
        try:
            if isinstance(ledger_data, dict) and "entries" in ledger_data:
                self.ledger = ledger_data.get("entries", {})
                self.tx_counter = ledger_data.get("tx_counter", 0)
                self.last_hash = ledger_data.get("last_hash", None)
                print(f"✓ Imported blockchain with {len(self.ledger)} entries")
                return True
            else:
                print("✗ Invalid ledger format for import")
                return False
        except Exception as e:
            print(f"✗ Failed to import ledger: {e}")
            return False
