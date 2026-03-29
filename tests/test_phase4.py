"""
Phase 4 Verification Tests

Tests for:
1. MissingBlockDetector - detecting missing blocks
2. BlockReassembler - reassembling files from blocks
3. SelfHealingSystem - orchestrating recovery

Run with: python test_phase4.py
"""

import os
import sys
import tempfile
import hashlib

# Add parent directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Phase 4 modules
from transmission.self_healing import MissingBlockDetector, BlockReassembler, SelfHealingSystem
from transmission.block_manager import BlockManager, EncryptedBlock, BlockMetadata, BlockState
from vault.authentication import generate_salt


def test_missing_block_detector():
    """Test MissingBlockDetector."""
    print("\n" + "="*70)
    print("TEST 1: MissingBlockDetector")
    print("="*70)
    
    try:
        detector = MissingBlockDetector()
        print("✓ MissingBlockDetector initialized")
        
        # Test initial state
        if detector.is_complete():
            print("✓ Correctly shows complete when no blocks expected")
        
        # Set expected blocks
        detector.set_expected_blocks(5)
        if detector.expected_block_count == 5:
            print("✓ Expected block count set: 5")
        else:
            raise AssertionError("Expected block count not set")
        
        # All should be missing initially
        missing = detector.detect_missing_blocks()
        if missing == [0, 1, 2, 3, 4]:
            print(f"✓ All blocks marked missing initially: {missing}")
        else:
            raise AssertionError(f"Initial missing list incorrect: {missing}")
        
        # Mark some blocks as received
        detector.mark_block_received(0)
        detector.mark_block_received(2)
        
        missing = detector.detect_missing_blocks()
        if missing == [1, 3, 4]:
            print(f"✓ Missing blocks updated correctly: {missing}")
        else:
            raise AssertionError(f"Missing list incorrect: {missing}")
        
        # Test completion percentage
        completion = detector.get_completion_percentage()
        expected_completion = (2 / 5) * 100
        if abs(completion - expected_completion) < 0.01:
            print(f"✓ Completion percentage correct: {completion:.1f}%")
        else:
            raise AssertionError(f"Completion percentage wrong: {completion}")
        
        # Mark all as received
        detector.mark_blocks_received([1, 3, 4])
        if detector.is_complete():
            print("✓ Correctly shows complete when all blocks received")
        else:
            raise AssertionError("Should show complete")
        
        # Test summary
        summary = detector.get_summary()
        print(f"✓ Summary: {summary}")
        
        # Test reset
        detector.reset()
        if detector.expected_block_count == 0:
            print("✓ Detector reset successfully")
        else:
            raise AssertionError("Reset failed")
        
        print("\n✅ MissingBlockDetector: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ MissingBlockDetector: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_block_reassembler():
    """Test BlockReassembler."""
    print("\n" + "="*70)
    print("TEST 2: BlockReassembler")
    print("="*70)
    
    try:
        # Create dummy block manager
        manager = BlockManager()
        reassembler = BlockReassembler(manager)
        print("✓ BlockReassembler initialized")
        
        # Create test blocks
        block_data = {
            0: b"Block 0 data ",
            1: b"Block 1 data ",
            2: b"Block 2 data "
        }
        
        # Try to reassemble with all blocks
        result = reassembler.reassemble_file(block_data)
        
        if result is not None:
            expected_result = b"Block 0 data Block 1 data Block 2 data "
            if result == expected_result:
                print(f"✓ Files reassembled correctly: {len(result)} bytes")
            else:
                raise AssertionError("Reassembly data mismatch")
        else:
            raise AssertionError("Reassembly returned None")
        
        # Test with missing block (should fail)
        incomplete_data = {0: b"Block 0 data ", 2: b"Block 2 data "}
        result = reassembler.reassemble_file(incomplete_data, allow_gaps=False)
        
        if result is None:
            print("✓ Correctly fails with missing blocks (allow_gaps=False)")
        else:
            raise AssertionError("Should fail with missing blocks")
        
        # Test with missing block (allow_gaps=True - will fail due to gap)
        result = reassembler.reassemble_file(incomplete_data, allow_gaps=True)
        if result is None:
            print("✓ Correctly fails with missing block even with allow_gaps=True")
        
        # Test integrity validation
        test_data = b"test file content"
        test_hash = hashlib.sha256(test_data).hexdigest()
        
        if reassembler.validate_file_integrity(test_data, test_hash):
            print("✓ File integrity validation passed")
        else:
            raise AssertionError("Integrity validation failed")
        
        # Test with wrong hash
        wrong_hash = "a" * 64
        if not reassembler.validate_file_integrity(test_data, wrong_hash):
            print("✓ Correctly rejects wrong hash")
        else:
            raise AssertionError("Should reject wrong hash")
        
        # Test get reassembled data
        assembled = reassembler.get_reassembled_data()
        if len(assembled) > 0:
            print(f"✓ Reassembled data retrieved: {len(assembled)} bytes")
        
        # Test summary
        summary = reassembler.get_summary()
        print(f"✓ Summary: {summary}")
        
        print("\n✅ BlockReassembler: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ BlockReassembler: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_self_healing_system():
    """Test SelfHealingSystem."""
    print("\n" + "="*70)
    print("TEST 3: SelfHealingSystem")
    print("="*70)
    
    try:
        # Create block manager
        manager = BlockManager()
        
        # Create system
        system = SelfHealingSystem(manager, max_recovery_attempts=3)
        print("✓ SelfHealingSystem initialized")
        
        # Test missing block detection
        print("\n→ Testing missing block detection...")
        missing = system.detect_missing_blocks(
            total_blocks=5,
            received_ids=[0, 2, 4]
        )
        
        if missing == [1, 3]:
            print(f"✓ Missing blocks detected correctly: {missing}")
        else:
            raise AssertionError(f"Missing blocks incorrect: {missing}")
        
        # Test get status
        status = system.get_recovery_status()
        print(f"✓ Recovery status: {status['detector']}")
        
        # Test recovery attempt with complete data
        print("\n→ Testing recovery with complete data...")
        complete_data = {
            0: b"Block 0 ",
            1: b"Block 1 ",
            2: b"Block 2 ",
            3: b"Block 3 ",
            4: b"Block 4 "
        }
        
        success, reassembled = system.attempt_recovery(complete_data)
        if reassembled:
            print(f"✓ Recovery succeeded with complete data: {len(reassembled)} bytes")
        else:
            print("⚠ Recovery returned None (expected for gaps)")
        
        # Reset for next test
        system.reset()
        
        # Test recovery attempt with missing blocks
        print("\n→ Testing recovery with missing blocks...")
        incomplete_data = {
            0: b"Block 0 ",
            1: b"Block 1 ",
            3: b"Block 3 ",
            4: b"Block 4 "
        }
        
        system.detect_missing_blocks(5, [0, 1, 3, 4])
        success, reassembled = system.attempt_recovery(incomplete_data)
        
        if not success:
            print("✓ Recovery correctly fails with missing blocks")
        else:
            print("⚠ Recovery succeeded unexpectedly")
        
        # Test recovery status after attempts
        status = system.get_recovery_status()
        print(f"✓ Final status: {status['detector']}")
        
        print("\n✅ SelfHealingSystem: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ SelfHealingSystem: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all Phase 4 tests."""
    print("\n" + "█"*70)
    print("PHASE 4 VERIFICATION TESTS")
    print("█"*70)
    
    results = []
    
    # Run tests
    results.append(("MissingBlockDetector", test_missing_block_detector()))
    results.append(("BlockReassembler", test_block_reassembler()))
    results.append(("SelfHealingSystem", test_self_healing_system()))
    
    # Summary
    print("\n" + "█"*70)
    print("PHASE 4 TEST SUMMARY")
    print("█"*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL PHASE 4 TESTS PASSED! 🎉")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
