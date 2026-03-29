"""
Phase 3 Verification Tests

Tests for:
1. BlockTransmitter - sending blocks with checksums
2. BlockReceiver - receiving blocks and validating checksums
3. TransmissionManager - end-to-end workflow (simplified)

Run with: python test_phase3.py
"""

import os
import sys
import tempfile
import threading
import time
from typing import Optional

# Add parent directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Phase 3 modules
from transmission.network_transmitter import BlockTransmitter
from transmission.network_receiver import BlockReceiver
from transmission.transmission_manager import TransmissionManager
from transmission.block_manager import EncryptedBlock, BlockMetadata, BlockState
from vault.authentication import derive_key, generate_salt


def test_block_transmitter():
    """Test BlockTransmitter basic functionality."""
    print("\n" + "="*70)
    print("TEST 1: BlockTransmitter")
    print("="*70)
    
    try:
        transmitter = BlockTransmitter(max_retries=2, timeout=5.0)
        print("✓ BlockTransmitter initialized")
        
        # Test without connection (should fail)
        if not transmitter.is_connected():
            print("✓ Correctly reports not connected")
        else:
            raise AssertionError("Should report not connected initially")
        
        # Create test block
        key = generate_salt(32)
        plaintext = b"Test block data" * 100
        
        from encryption import encrypt_aes_256
        encrypted_data = encrypt_aes_256(key, plaintext)
        
        test_block = EncryptedBlock(
            block_id=0,
            original_metadata=BlockMetadata(0, 0, len(plaintext), 0, len(plaintext)),
            plaintext_size=len(plaintext),
            encrypted_data=encrypted_data,
            encrypted_size=len(encrypted_data),
            encryption_method="AES-256",
            plaintext_hash="test_hash_0"
        )
        
        # Test checksum calculation (should not fail)
        checksum = transmitter._calculate_checksum(encrypted_data)
        print(f"✓ Checksum calculated: {checksum:#x}")
        
        # Reset stats
        transmitter.reset_stats()
        stats = transmitter.get_transmission_stats()
        if stats['blocks_sent'] == 0:
            print("✓ Stats reset correctly")
        else:
            raise AssertionError("Stats not reset")
        
        # Get summary (should reflect no transmissions)
        summary = transmitter.get_summary()
        if "Blocks sent: 0" in summary:
            print(f"✓ Summary: {summary}")
        else:
            raise AssertionError(f"Summary incorrect: {summary}")
        
        print("\n✅ BlockTransmitter: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ BlockTransmitter: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_block_receiver():
    """Test BlockReceiver basic functionality."""
    print("\n" + "="*70)
    print("TEST 2: BlockReceiver")
    print("="*70)
    
    try:
        receiver = BlockReceiver(port=9999, timeout=5.0)
        print("✓ BlockReceiver initialized")
        
        # Verify initial state
        if not receiver.is_listening:
            print("✓ Correctly reports not listening initially")
        else:
            raise AssertionError("Should not be listening initially")
        
        # Check missing blocks on empty receiver
        missing = receiver.get_missing_blocks(5)
        if missing == [0, 1, 2, 3, 4]:
            print(f"✓ Missing blocks correctly identified: {missing}")
        else:
            raise AssertionError(f"Missing blocks incorrect: {missing}")
        
        # Simulate received blocks
        receiver.received_blocks[0] = b"block_0_data"
        receiver.received_blocks[2] = b"block_2_data"
        receiver.block_count = 2
        
        # Check missing again
        missing = receiver.get_missing_blocks(5)
        if missing == [1, 3, 4]:
            print(f"✓ Missing blocks updated correctly: {missing}")
        else:
            raise AssertionError(f"Missing blocks incorrect: {missing}")
        
        # Test checksum calculation
        test_data = b"test_data_for_checksum"
        checksum = receiver._calculate_checksum(test_data)
        print(f"✓ Checksum calculated: {checksum:#x}")
        
        # Test get_block_data
        block_data = receiver.get_block_data(0)
        if block_data == b"block_0_data":
            print("✓ Block data retrieved correctly")
        else:
            raise AssertionError("Block data retrieval failed")
        
        # Test is_block_received
        if receiver.is_block_received(0) and not receiver.is_block_received(1):
            print("✓ Block received check works correctly")
        else:
            raise AssertionError("Block received check failed")
        
        # Test statistics
        stats = receiver.get_reception_stats()
        print(f"✓ Statistics: {stats}")
        
        # Test summary
        summary = receiver.get_summary()
        print(f"✓ Summary: {summary}")
        
        # Reset
        receiver.reset()
        if len(receiver.received_blocks) == 0:
            print("✓ Receiver reset successfully")
        else:
            raise AssertionError("Reset failed")
        
        print("\n✅ BlockReceiver: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ BlockReceiver: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_transmission_manager_metadata():
    """Test TransmissionManager metadata and key management."""
    print("\n" + "="*70)
    print("TEST 3: TransmissionManager (Metadata & Key Management)")
    print("="*70)
    
    try:
        manager = TransmissionManager(vault_password="test_password")
        print("✓ TransmissionManager initialized")
        
        # Check key generation
        if manager.master_key and len(manager.master_key) == 32:
            print(f"✓ Master key generated ({len(manager.master_key)} bytes)")
        else:
            raise AssertionError("Master key not properly generated")
        
        # Check salt
        if manager.salt and len(manager.salt) == 16:
            print(f"✓ Salt generated ({len(manager.salt)} bytes)")
        else:
            raise AssertionError("Salt not properly generated")
        
        # Check components initialized
        if manager.block_splitter and manager.block_hasher and manager.block_manager:
            print("✓ Core components initialized")
        else:
            raise AssertionError("Components not initialized")
        
        # Check blockchain
        if manager.blockchain:
            print("✓ Blockchain initialized")
        else:
            raise AssertionError("Blockchain not initialized")
        
        # Test getting status
        status = manager.get_transmission_status()
        if status['mode'] is None:
            print("✓ Status correctly shows idle mode")
        else:
            raise AssertionError(f"Status mode incorrect: {status['mode']}")
        
        print("\n✅ TransmissionManager (Metadata): PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ TransmissionManager (Metadata): FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_transmission_manager_file_sending():
    """Test TransmissionManager file preparation for sending."""
    print("\n" + "="*70)
    print("TEST 4: TransmissionManager (File Preparation)")
    print("="*70)
    
    try:
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            test_file = f.name
            test_data = b"Hello World! " * 100  # Small test file
            f.write(test_data)
        
        manager = TransmissionManager()
        print(f"✓ Test file created: {test_file}")
        
        # Test block splitting (without actual network transmission)
        print("✓ Splitting file into blocks...")
        manager.block_splitter.block_size = 512  # Small blocks for testing
        blocks_meta = manager.block_splitter.split_file(test_file)
        
        if len(blocks_meta) > 0:
            print(f"✓ File split into {len(blocks_meta)} blocks")
        else:
            raise AssertionError("No blocks created")
        
        # Register blocks in hasher
        manager.block_hasher.register_blocks(blocks_meta)
        
        # Test encryption of blocks
        print("✓ Encrypting blocks...")
        encrypted_count = 0
        
        for block_meta in blocks_meta:
            block_data = manager.block_splitter.read_block_data(test_file, block_meta)
            
            # Encrypt
            encrypted_data, method = manager.adaptive_encryptor.encrypt_block(
                block_id=block_meta.block_id,
                block_data=block_data,
                encryption_key=manager.master_key
            )
            
            # Hash
            plaintext_hash = manager.block_hasher.hash_block(
                block_id=block_meta.block_id,
                block_data=block_data,
                plaintext_size=len(block_data)
            )
            
            # Create encrypted block
            enc_block = EncryptedBlock(
                block_id=block_meta.block_id,
                original_metadata=block_meta,
                plaintext_size=len(block_data),
                encrypted_data=encrypted_data,
                encrypted_size=len(encrypted_data),
                encryption_method=method,
                plaintext_hash=plaintext_hash
            )
            
            manager.block_manager.add_block(enc_block)
            encrypted_count += 1
        
        if encrypted_count == len(blocks_meta):
            print(f"✓ All {encrypted_count} blocks encrypted successfully")
        else:
            raise AssertionError(f"Encryption count mismatch: {encrypted_count} != {len(blocks_meta)}")
        
        # Register in blockchain
        print("✓ Registering hashes in blockchain...")
        for block_id, hash_value in manager.block_hasher.get_all_hashes().items():
            manager.blockchain.add_hash(block_id, hash_value, sender="test")
        
        if manager.blockchain.get_transaction_count() == len(blocks_meta):
            print(f"✓ {manager.blockchain.get_transaction_count()} hashes registered")
        else:
            raise AssertionError("Blockchain registration failed")
        
        # Test metadata saving
        manager._save_transmission_metadata(test_file, blocks_meta)
        if manager.transmission_metadata:
            print(f"✓ Metadata saved: {manager.transmission_metadata['file_name']}")
        else:
            raise AssertionError("Metadata not saved")
        
        # Cleanup
        os.unlink(test_file)
        
        print("\n✅ TransmissionManager (File Preparation): PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ TransmissionManager (File Preparation): FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all Phase 3 tests."""
    print("\n" + "█"*70)
    print("PHASE 3 VERIFICATION TESTS")
    print("█"*70)
    
    results = []
    
    # Run tests
    results.append(("BlockTransmitter", test_block_transmitter()))
    results.append(("BlockReceiver", test_block_receiver()))
    results.append(("TransmissionManager (Metadata)", test_transmission_manager_metadata()))
    results.append(("TransmissionManager (File Prep)", test_transmission_manager_file_sending()))
    
    # Summary
    print("\n" + "█"*70)
    print("PHASE 3 TEST SUMMARY")
    print("█"*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL PHASE 3 TESTS PASSED! 🎉")
        print("\nNote: Full end-to-end network tests require separate transmitter/receiver processes")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
