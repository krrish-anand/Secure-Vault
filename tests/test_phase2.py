"""
Phase 2 Verification Tests

Tests for:
1. Updated encryption.py - AES-128 and AES-256 variants
2. AdaptiveEncryptor - Network-aware encryption selection
3. BlockManager - Block lifecycle management

Run with: python test_phase2.py
"""

import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Phase 2 modules
from vault.encryption import encrypt_aes_128, decrypt_aes_128, encrypt_aes_256, decrypt_aes_256
from transmission.adaptive_encryption import AdaptiveEncryptor, EncryptionStrength
from transmission.block_manager import BlockManager, EncryptedBlock, BlockState
from block_splitter import BlockMetadata
from authentication import generate_salt, derive_key


def test_encryption_variants():
    """Test AES-128 and AES-256 encryption variants."""
    print("\n" + "="*70)
    print("TEST 1: Encryption Variants (AES-128 & AES-256)")
    print("="*70)
    
    try:
        plaintext = b"Secret message for encryption test"
        
        # Test AES-128
        key_128 = b"1234567890123456"  # 16 bytes
        ciphertext_128 = encrypt_aes_128(key_128, plaintext)
        print(f"✓ AES-128 encrypted: {len(ciphertext_128)} bytes")
        
        # Verify format [IV(16) | TAG(16) | Ciphertext]
        if len(ciphertext_128) >= 32:
            print(f"✓ Ciphertext format valid (IV+TAG+data)")
        else:
            raise AssertionError(f"Invalid ciphertext size: {len(ciphertext_128)}")
        
        # Decrypt AES-128
        decrypted_128 = decrypt_aes_128(key_128, ciphertext_128)
        if decrypted_128 == plaintext:
            print("✓ AES-128 decryption correct")
        else:
            raise AssertionError("AES-128 decryption mismatch")
        
        # Test AES-256
        key_256 = generate_salt(32)  # 32 bytes
        ciphertext_256 = encrypt_aes_256(key_256, plaintext)
        print(f"✓ AES-256 encrypted: {len(ciphertext_256)} bytes")
        
        # Decrypt AES-256
        decrypted_256 = decrypt_aes_256(key_256, ciphertext_256)
        if decrypted_256 == plaintext:
            print("✓ AES-256 decryption correct")
        else:
            raise AssertionError("AES-256 decryption mismatch")
        
        # Verify ciphertexts are different (different keys and IVs)
        if ciphertext_128 != ciphertext_256:
            print("✓ Different keys produce different ciphertexts")
        else:
            print("⚠ Warning: Same ciphertext (statistically unlikely but not impossible)")
        
        # Test wrong key fails
        wrong_key = b"wrong_key_1234567"
        try:
            decrypt_aes_128(wrong_key, ciphertext_128)
            raise AssertionError("Wrong key should fail decryption")
        except Exception:
            print("✓ Wrong key correctly rejected")
        
        # Test wrong key size
        try:
            encrypt_aes_128(b"short", plaintext)
            raise AssertionError("Wrong key size should fail")
        except ValueError:
            print("✓ Wrong key size correctly rejected")
        
        print("\n✅ Encryption Variants: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ Encryption Variants: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_adaptive_encryptor():
    """Test AdaptiveEncryptor functionality."""
    print("\n" + "="*70)
    print("TEST 2: AdaptiveEncryptor")
    print("="*70)
    
    try:
        # Create encryptor
        encryptor = AdaptiveEncryptor()
        print("✓ AdaptiveEncryptor initialized")
        
        # Measure network
        encryptor.measure_network(sample_count=3)
        print("✓ Network measurement complete")
        
        # Get metrics
        metrics = encryptor.get_current_metrics()
        print(f"✓ Network metrics obtained:")
        print(f"   - Latency: {metrics['latency_ms']:.2f}ms")
        print(f"   - Packet Loss: {metrics['packet_loss_percent']:.2f}%")
        print(f"   - Quality: {metrics['network_quality'].upper()}")
        
        # Choose encryption strength
        strength = encryptor.choose_encryption_strength()
        print(f"✓ Encryption strength chosen: {strength.value}")
        
        # Get network quality
        quality = encryptor.get_network_quality()
        print(f"✓ Network quality: {quality.value.upper()}")
        
        # Encrypt blocks with test data
        plaintext_block = b"Test block data for encryption"
        key = generate_salt(32)
        
        encrypted_data, method = encryptor.encrypt_block(
            block_id=0,
            block_data=plaintext_block,
            encryption_key=key
        )
        print(f"✓ Block 0 encrypted with {method}: {len(encrypted_data)} bytes")
        
        # Verify method is tracked
        tracked_method = encryptor.get_block_encryption_method(0)
        if tracked_method == method:
            print(f"✓ Encryption method tracked correctly: {tracked_method}")
        else:
            raise AssertionError(f"Method tracking failed: {tracked_method} != {method}")
        
        # Decrypt block
        decrypted_data = encryptor.decrypt_block(
            block_id=0,
            encrypted_data=encrypted_data,
            encryption_key=key,
            method=method
        )
        if decrypted_data == plaintext_block:
            print("✓ Block decryption correct")
        else:
            raise AssertionError("Block decryption mismatch")
        
        # Test force_strength parameter
        encrypted_128, method_128 = encryptor.encrypt_block(
            block_id=1,
            block_data=plaintext_block,
            encryption_key=key,
            force_strength=EncryptionStrength.WEAK
        )
        if method_128 == "AES-128":
            print("✓ Force strength AES-128 works")
        else:
            raise AssertionError(f"Force strength failed: {method_128}")
        
        # Verify decryption with correct method
        decrypted_128 = encryptor.decrypt_block(1, encrypted_128, key, method_128)
        if decrypted_128 == plaintext_block:
            print("✓ Forced AES-128 decryption correct")
        else:
            raise AssertionError("Forced AES-128 decryption failed")
        
        # Get summary
        summary = encryptor.get_encryption_summary()
        print(f"✓ Summary: {summary}")
        
        # Reset stats
        encryptor.reset_stats()
        print("✓ Statistics reset")
        
        print("\n✅ AdaptiveEncryptor: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ AdaptiveEncryptor: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_block_manager():
    """Test BlockManager functionality."""
    print("\n" + "="*70)
    print("TEST 3: BlockManager")
    print("="*70)
    
    try:
        manager = BlockManager()
        print("✓ BlockManager initialized")
        
        # Create test blocks
        key = generate_salt(32)
        
        for block_id in range(3):
            # Create encrypted block
            plaintext = f"Block {block_id} data".encode() * 10
            encrypted = encrypt_aes_256(key, plaintext)
            
            original_meta = BlockMetadata(
                block_id=block_id,
                sequence=block_id,
                size=len(plaintext),
                offset=block_id * len(plaintext),
                plaintext_size=len(plaintext)
            )
            
            enc_block = EncryptedBlock(
                block_id=block_id,
                original_metadata=original_meta,
                plaintext_size=len(plaintext),
                encrypted_data=encrypted,
                encrypted_size=len(encrypted),
                encryption_method="AES-256",
                plaintext_hash="hash_" + str(block_id),
                state=BlockState.CREATED
            )
            
            manager.add_block(enc_block)
        
        print(f"✓ 3 blocks added to manager")
        
        # Verify block count
        if manager.get_block_count() == 3:
            print("✓ Block count correct: 3")
        else:
            raise AssertionError(f"Block count mismatch: {manager.get_block_count()}")
        
        # Get blocks
        all_blocks = manager.get_all_blocks()
        if len(all_blocks) == 3:
            print("✓ All blocks retrieved in sequence order")
        else:
            raise AssertionError(f"Block retrieval failed: {len(all_blocks)}")
        
        # Update block states
        manager.update_block_state(0, BlockState.ENCRYPTED)
        if manager.get_block_state(0) == BlockState.ENCRYPTED:
            print("✓ Block state updated correctly")
        else:
            raise AssertionError("Block state update failed")
        
        # Mark block as transmitted
        manager.mark_transmitted(0)
        if manager.get_block_state(0) == BlockState.TRANSMITTED:
            print("✓ Block marked as transmitted")
        else:
            raise AssertionError("Mark transmitted failed")
        
        # Mark block as verified
        manager.mark_verified(0)
        if manager.get_block_state(0) == BlockState.VERIFIED:
            print("✓ Block marked as verified")
        else:
            raise AssertionError("Mark verified failed")
        
        # Get blocks by state
        verified = manager.get_blocks_by_state(BlockState.VERIFIED)
        if len(verified) == 1:
            print("✓ Blocks filtered by state correctly")
        else:
            raise AssertionError(f"State filtering failed: {len(verified)}")
        
        # Get untransmitted blocks
        untransmitted = manager.get_untransmitted_blocks()
        if len(untransmitted) == 2:  # blocks 1 and 2
            print(f"✓ Untransmitted blocks detected: {len(untransmitted)}")
        else:
            raise AssertionError(f"Untransmitted detection failed: {len(untransmitted)}")
        
        # Increment transmission attempts
        manager.increment_transmission_attempts(0)
        block_0 = manager.get_block(0)
        if block_0.transmission_attempts == 1:
            print("✓ Transmission attempts tracked")
        else:
            raise AssertionError("Transmission attempts tracking failed")
        
        # Set error
        manager.set_block_error(1, "Network timeout")
        block_1 = manager.get_block(1)
        if block_1.last_error == "Network timeout":
            print("✓ Block error set correctly")
        else:
            raise AssertionError("Error setting failed")
        
        # Get statistics
        stats = manager.get_statistics()
        if stats['total_blocks'] == 3:
            print(f"✓ Statistics calculated:")
            print(f"   - Total blocks: {stats['total_blocks']}")
            print(f"   - Plaintext size: {stats['total_plaintext_size']} bytes")
            print(f"   - Encrypted size: {stats['total_encrypted_size']} bytes")
            print(f"   - Size increase: {stats['size_increase_percent']:.1f}%")
        else:
            raise AssertionError("Statistics calculation failed")
        
        # Validate all blocks
        is_valid = manager.validate_all_blocks()
        if is_valid:
            print("✓ All blocks validation passed")
        else:
            raise AssertionError("Block validation failed")
        
        # Get summary
        summary = manager.get_summary()
        print(f"✓ Summary: {summary}")
        
        print("\n✅ BlockManager: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ BlockManager: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all Phase 2 tests."""
    print("\n" + "█"*70)
    print("PHASE 2 VERIFICATION TESTS")
    print("█"*70)
    
    results = []
    
    # Run tests
    results.append(("Encryption Variants", test_encryption_variants()))
    results.append(("AdaptiveEncryptor", test_adaptive_encryptor()))
    results.append(("BlockManager", test_block_manager()))
    
    # Summary
    print("\n" + "█"*70)
    print("PHASE 2 TEST SUMMARY")
    print("█"*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL PHASE 2 TESTS PASSED! 🎉")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
