"""
Phase 1 Verification Tests

Tests for:
1. NetworkMonitor - latency/packet loss measurement
2. BlockSplitter - file splitting into blocks
3. BlockHasher - SHA-256 hashing per block
4. MockBlockchain - blockchain ledger verification

Run with: python test_phase1.py
"""

import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Phase 1 modules
from transmission.network_intelligence import NetworkMonitor, NetworkQuality
from transmission.block_splitter import BlockSplitter, BlockMetadata
from transmission.block_hasher import BlockHasher
from transmission.mock_blockchain import MockBlockchain


def test_network_monitor():
    """Test NetworkMonitor functionality."""
    print("\n" + "="*70)
    print("TEST 1: NetworkMonitor")
    print("="*70)
    
    try:
        monitor = NetworkMonitor(target_host="8.8.8.8", target_port=53)
        print("✓ NetworkMonitor initialized")
        
        # Measure latency (use reduced sample count for speed)
        latency = monitor.measure_latency(sample_count=3)
        print(f"✓ Latency measured: {latency:.2f}ms")
        
        # Measure packet loss
        loss = monitor.measure_packet_loss(sample_count=3)
        print(f"✓ Packet loss measured: {loss:.2f}%")
        
        # Get network quality
        quality = monitor.get_network_quality()
        print(f"✓ Network quality: {quality.value.upper()}")
        
        # Calculate metrics
        metrics = monitor.calculate_metrics()
        print(f"✓ Metrics calculated:")
        print(f"   - Avg Latency: {metrics.avg_latency_ms:.2f}ms")
        print(f"   - Packet Loss: {metrics.packet_loss_percent:.2f}%")
        print(f"   - Sample Count: {metrics.sample_count}")
        
        # Get summary
        summary = monitor.get_summary()
        print(f"✓ Summary: {summary}")
        
        print("\n✅ NetworkMonitor: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ NetworkMonitor: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_block_splitter():
    """Test BlockSplitter functionality."""
    print("\n" + "="*70)
    print("TEST 2: BlockSplitter")
    print("="*70)
    
    try:
        # Create test file
        test_data = b"Hello World! " * 10000  # ~130KB test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_file = f.name
            f.write(test_data)
        
        print(f"✓ Test file created: {len(test_data)} bytes")
        
        # Initialize splitter with 64KB blocks
        splitter = BlockSplitter(block_size=65536)
        print("✓ BlockSplitter initialized (block_size=64KB)")
        
        # Split file
        blocks = splitter.split_file(test_file)
        print(f"✓ File split into {len(blocks)} blocks")
        
        # Verify block count
        expected_blocks = (len(test_data) + 65535) // 65536
        if len(blocks) == expected_blocks:
            print(f"✓ Block count correct: {len(blocks)} == {expected_blocks}")
        else:
            raise AssertionError(f"Block count mismatch: {len(blocks)} != {expected_blocks}")
        
        # Verify block structure
        is_valid = splitter.validate_block_structure()
        if is_valid:
            print("✓ Block structure valid (contiguous, correct offsets)")
        else:
            raise AssertionError("Block structure validation failed")
        
        # Verify block metadata
        for block in blocks:
            if block.block_id < 0 or block.size <= 0:
                raise AssertionError(f"Invalid block metadata: {block}")
        print("✓ All block metadata valid")
        
        # Read and verify block data
        block_zero = blocks[0]
        block_data = splitter.read_block_data(test_file, block_zero)
        if len(block_data) == block_zero.size:
            print(f"✓ Block data read correctly: {len(block_data)} bytes")
        else:
            raise AssertionError(f"Block data size mismatch: {len(block_data)} != {block_zero.size}")
        
        # Test get_missing_blocks
        received = [0, 1]  # Simulate receiving blocks 0 and 1
        missing = splitter.get_missing_blocks(received)
        expected_missing = list(range(2, len(blocks)))
        if missing == expected_missing:
            print(f"✓ Missing blocks detected correctly: {missing}")
        else:
            raise AssertionError(f"Missing blocks mismatch: {missing} != {expected_missing}")
        
        # Get summary
        summary = splitter.get_summary()
        print(f"✓ Summary: {summary}")
        
        # Cleanup
        os.unlink(test_file)
        
        print("\n✅ BlockSplitter: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ BlockSplitter: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_block_hasher():
    """Test BlockHasher functionality."""
    print("\n" + "="*70)
    print("TEST 3: BlockHasher")
    print("="*70)
    
    try:
        hasher = BlockHasher()
        print("✓ BlockHasher initialized")
        
        # Create test blocks
        block_data_1 = b"Block 1 data content"
        block_data_2 = b"Block 2 data content"
        
        # Hash blocks
        hash_1 = hasher.hash_block(block_id=0, block_data=block_data_1, plaintext_size=len(block_data_1))
        hash_2 = hasher.hash_block(block_id=1, block_data=block_data_2, plaintext_size=len(block_data_2))
        print(f"✓ Block 0 hashed: {hash_1[:16]}...")
        print(f"✓ Block 1 hashed: {hash_2[:16]}...")
        
        # Verify hash format (SHA-256 = 64 hex chars)
        if len(hash_1) == 64 and len(hash_2) == 64:
            print("✓ Hash format valid (64 hex characters)")
        else:
            raise AssertionError(f"Hash format invalid: {len(hash_1)}, {len(hash_2)}")
        
        # Verify hashes are different
        if hash_1 != hash_2:
            print("✓ Different blocks produce different hashes")
        else:
            raise AssertionError("Hash collision detected!")
        
        # Verify block
        is_valid = hasher.verify_block(block_id=0, block_data=block_data_1)
        if is_valid:
            print("✓ Block 0 verification passed")
        else:
            raise AssertionError("Block 0 verification failed")
        
        # Verify with wrong data
        is_valid = hasher.verify_block(block_id=0, block_data=b"Wrong data")
        if not is_valid:
            print("✓ Invalid data correctly rejected")
        else:
            raise AssertionError("Invalid data incorrectly accepted")
        
        # Get all hashes
        all_hashes = hasher.get_all_hashes()
        if len(all_hashes) == 2 and 0 in all_hashes and 1 in all_hashes:
            print(f"✓ All hashes retrieved: {len(all_hashes)} blocks")
        else:
            raise AssertionError(f"Hashes retrieval failed: {all_hashes}")
        
        # Register block metadata and get info
        block_meta = BlockMetadata(
            block_id=0,
            sequence=0,
            size=len(block_data_1),
            offset=0,
            plaintext_size=len(block_data_1)
        )
        hasher.register_block_metadata(block_meta)
        info = hasher.get_block_info(block_id=0)
        if info and "hash" in info and "offset" in info:
            print("✓ Block info retrieved with metadata")
        else:
            raise AssertionError("Block info retrieval failed")
        
        # Get summary
        summary = hasher.get_summary()
        print(f"✓ Summary: {summary}")
        
        print("\n✅ BlockHasher: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ BlockHasher: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_mock_blockchain():
    """Test MockBlockchain functionality."""
    print("\n" + "="*70)
    print("TEST 4: MockBlockchain")
    print("="*70)
    
    try:
        # Use temporary file for ledger
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = os.path.join(tmpdir, "test_blockchain.ledger")
            
            blockchain = MockBlockchain(ledger_path=ledger_path)
            print("✓ MockBlockchain initialized")
            
            # Add hashes
            tx_id_1 = blockchain.add_hash(
                block_id=0,
                block_hash="a" * 64,  # 64-char hex hash
                sender="sender_1"
            )
            print(f"✓ Hash added: tx_id={tx_id_1}")
            
            tx_id_2 = blockchain.add_hash(
                block_id=1,
                block_hash="b" * 64,
                sender="sender_2"
            )
            print(f"✓ Second hash added: tx_id={tx_id_2}")
            
            # Verify blockchain integrity
            is_valid = blockchain.is_valid()
            if is_valid:
                print("✓ Blockchain integrity verified")
            else:
                raise AssertionError("Blockchain integrity check failed")
            
            # Verify hash
            if blockchain.verify_hash(block_id=0, block_hash="a" * 64):
                print("✓ Hash verification passed")
            else:
                raise AssertionError("Hash verification failed")
            
            # Verify wrong hash
            if not blockchain.verify_hash(block_id=0, block_hash="c" * 64):
                print("✓ Invalid hash correctly rejected")
            else:
                raise AssertionError("Invalid hash incorrectly accepted")
            
            # Get hash
            stored_hash = blockchain.get_hash(block_id=0)
            if stored_hash == "a" * 64:
                print("✓ Hash retrieval correct")
            else:
                raise AssertionError("Hash retrieval incorrect")
            
            # Get transaction entry
            entry = blockchain.get_entry(tx_id_1)
            if entry and entry["block_id"] == 0:
                print("✓ Transaction entry retrieved")
            else:
                raise AssertionError("Transaction retrieval failed")
            
            # Get chain
            chain = blockchain.get_chain()
            if len(chain) == 2:
                print(f"✓ Blockchain chain retrieved: {len(chain)} entries")
            else:
                raise AssertionError(f"Chain size mismatch: {len(chain)} != 2")
            
            # Get all block hashes
            all_hashes = blockchain.get_all_block_hashes()
            if len(all_hashes) == 2 and 0 in all_hashes and 1 in all_hashes:
                print(f"✓ All block hashes exported: {len(all_hashes)} blocks")
            else:
                raise AssertionError(f"Hash export failed: {all_hashes}")
            
            # Verify persistence
            blockchain2 = MockBlockchain(ledger_path=ledger_path)
            if blockchain2.get_transaction_count() == 2:
                print("✓ Ledger persistence verified (reload from disk)")
            else:
                raise AssertionError("Ledger persistence failed")
            
            # Get summary
            summary = blockchain.get_summary()
            print(f"✓ Summary: {summary}")
            
            # Export ledger
            export = blockchain.export_ledger()
            if "entries" in export and "is_valid" in export:
                print("✓ Ledger exported successfully")
            else:
                raise AssertionError("Ledger export failed")
        
        print("\n✅ MockBlockchain: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ MockBlockchain: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all Phase 1 tests."""
    print("\n" + "█"*70)
    print("PHASE 1 VERIFICATION TESTS")
    print("█"*70)
    
    results = []
    
    # Run tests
    results.append(("NetworkMonitor", test_network_monitor()))
    results.append(("BlockSplitter", test_block_splitter()))
    results.append(("BlockHasher", test_block_hasher()))
    results.append(("MockBlockchain", test_mock_blockchain()))
    
    # Summary
    print("\n" + "█"*70)
    print("PHASE 1 TEST SUMMARY")
    print("█"*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL PHASE 1 TESTS PASSED! 🎉")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
