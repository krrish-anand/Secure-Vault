"""
RSA Key Management Security Tests
Tests for RSA-2048 key generation, encryption/decryption, signatures, and session key exchange.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path for imports
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from transmission.key_management import KeyManager, SessionKeyManager


def print_test_header(test_num: int, title: str):
    """Print formatted test header."""
    print(f"\n{'='*70}")
    print(f"TEST {test_num}: {title}")
    print(f"{'='*70}")


def print_test_result(passed: bool, details: str = ""):
    """Print test result."""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status}\n{details if details else ''}")


def test_1_rsa_key_generation():
    """Test RSA-2048 key pair generation."""
    print_test_header(1, "RSA Key Pair Generation")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        km = KeyManager(tmpdir)
        private_key, public_key = km.generate_key_pair()
        
        details = (
            f"✓ Private key generated: {type(private_key).__name__}\n"
            f"✓ Public key generated: {type(public_key).__name__}\n"
            f"✓ Key size: {km.RSA_KEY_SIZE} bits\n"
            f"✓ Public exponent: {km.RSA_E}"
        )
        
        passed = private_key is not None and public_key is not None
        print_test_result(passed, details)
        return passed


def test_2_key_saving_and_loading():
    """Test key persistence (save/load)."""
    print_test_header(2, "Key Saving and Loading")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Generate and save
        km1 = KeyManager(tmpdir)
        km1.generate_key_pair()
        km1.save_private_key("test_private.pem")
        km1.save_public_key("test_public.pem")
        
        private_pem_1 = km1.private_key.private_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.PEM,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PrivateFormat']).PrivateFormat.PKCS8,
            encryption_algorithm=__import__('cryptography.hazmat.primitives.serialization', fromlist=['NoEncryption']).NoEncryption()
        )
        
        # Load into new manager
        km2 = KeyManager(tmpdir)
        km2.load_private_key("test_private.pem")
        km2.load_public_key("test_public.pem")
        
        private_pem_2 = km2.private_key.private_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.PEM,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PrivateFormat']).PrivateFormat.PKCS8,
            encryption_algorithm=__import__('cryptography.hazmat.primitives.serialization', fromlist=['NoEncryption']).NoEncryption()
        )
        
        matched = private_pem_1 == private_pem_2
        
        details = (
            f"✓ Keys saved to files\n"
            f"✓ Keys loaded from disk\n"
            f"✓ Private keys match (round-trip): {matched}\n"
            f"✓ Public keys loaded successfully"
        )
        
        print_test_result(matched, details)
        return matched


def test_3_rsa_encryption_decryption():
    """Test RSA-OAEP encryption and decryption."""
    print_test_header(3, "RSA-OAEP Encryption/Decryption")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup two key managers for encrypted communication
        sender_km = KeyManager(tmpdir)
        receiver_km = KeyManager(tmpdir)
        
        sender_km.generate_key_pair()
        receiver_km.generate_key_pair()
        
        # Exchange public keys
        sender_km.peer_public_key = receiver_km.public_key
        receiver_km.peer_public_key = sender_km.public_key
        
        # Test message
        plaintext = b"This is a secret message for transmission"
        
        # Encrypt with receiver's public key
        ciphertext = sender_km.encrypt_with_public_key(plaintext)
        
        # Decrypt with receiver's private key
        decrypted = receiver_km.decrypt_with_private_key(ciphertext)
        
        matched = plaintext == decrypted
        
        details = (
            f"✓ Original message: {plaintext.decode()}\n"
            f"✓ Encrypted size: {len(ciphertext)} bytes (256 for RSA-2048)\n"
            f"✓ Decrypted message: {decrypted.decode()}\n"
            f"✓ Messages match: {matched}"
        )
        
        print_test_result(matched, details)
        return matched


def test_4_digital_signatures():
    """Test RSA-PSS digital signatures."""
    print_test_header(4, "RSA-PSS Digital Signatures")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        sender_km = KeyManager(tmpdir)
        receiver_km = KeyManager(tmpdir)
        
        sender_km.generate_key_pair()
        receiver_km.generate_key_pair()
        
        # Exchange public keys
        sender_km.peer_public_key = receiver_km.public_key
        receiver_km.peer_public_key = sender_km.public_key
        
        # Sender signs a message
        message = b"Sender: Starting secure transmission session"
        signature = sender_km.sign_data(message)
        
        # Receiver verifies signature
        is_valid = receiver_km.verify_signature(
            message, 
            signature, 
            sender_km.public_key
        )
        
        # Verify tampering detection
        tampered_message = b"Sender: Starting UNSECURE transmission session"
        is_valid_tampered = receiver_km.verify_signature(
            tampered_message,
            signature,
            sender_km.public_key
        )
        
        tampering_detected = not is_valid_tampered
        
        details = (
            f"✓ Message signed: {message.decode()}\n"
            f"✓ Signature size: {len(signature)} bytes (256 for RSA-2048)\n"
            f"✓ Valid signature verified: {is_valid}\n"
            f"✓ Tampering detected (invalid when message changed): {tampering_detected}"
        )
        
        passed = is_valid and tampering_detected
        print_test_result(passed, details)
        return passed


def test_5_session_key_management():
    """Test AES session key generation and RSA encryption."""
    print_test_header(5, "Session Key Management")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        sender_km = KeyManager(tmpdir)
        receiver_km = KeyManager(tmpdir)
        
        sender_km.generate_key_pair()
        receiver_km.generate_key_pair()
        
        # Exchange public keys
        sender_km.peer_public_key = receiver_km.public_key
        receiver_km.peer_public_key = sender_km.public_key
        
        # Sender creates and encrypts session key
        sender_skm = SessionKeyManager(sender_km)
        session_key = sender_skm.generate_aes_session_key(32)  # AES-256
        encrypted_session_key = sender_skm.encrypt_session_key(session_key)
        
        # Receiver decrypts session key
        receiver_skm = SessionKeyManager(receiver_km)
        decrypted_session_key = receiver_skm.decrypt_session_key(encrypted_session_key)
        
        matched = session_key == decrypted_session_key
        
        details = (
            f"✓ Generated AES-256 session key: {len(session_key)} bytes\n"
            f"✓ Encrypted session key: {len(encrypted_session_key)} bytes\n"
            f"✓ Decrypted session key: {len(decrypted_session_key)} bytes\n"
            f"✓ Keys match after encryption/decryption: {matched}"
        )
        
        print_test_result(matched, details)
        return matched


def test_6_complete_key_exchange_handshake():
    """Test complete RSA-based key exchange handshake."""
    print_test_header(6, "Complete Key Exchange Handshake")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # PHASE 1: Key pair generation
        print("  Phase 1: Key pair generation...")
        sender_km = KeyManager(tmpdir)
        receiver_km = KeyManager(tmpdir)
        
        sender_km.generate_key_pair()
        receiver_km.generate_key_pair()
        
        # PHASE 2: Public key exchange (simulated)
        print("  Phase 2: Public key exchange...")
        sender_public_pem = sender_km.get_public_key_pem()
        receiver_public_pem = receiver_km.get_public_key_pem()
        
        sender_km.load_public_key_from_pem(receiver_public_pem, as_peer=True)
        receiver_km.load_public_key_from_pem(sender_public_pem, as_peer=True)
        
        # PHASE 3: Session key generation and encryption
        print("  Phase 3: Session key generation...")
        sender_skm = SessionKeyManager(sender_km)
        session_key = sender_skm.generate_aes_session_key(32)
        encrypted_session_key = sender_skm.encrypt_session_key(session_key)
        
        # PHASE 4: Message signing
        print("  Phase 4: Message authentication...")
        handshake_message = b"Handshake:SK_Exchange:Session_Key_Ready"
        signature = sender_km.sign_data(handshake_message)
        
        # PHASE 5: Receiver side verification
        print("  Phase 5: Receiver verification...")
        receiver_skm = SessionKeyManager(receiver_km)
        decrypted_session_key = receiver_skm.decrypt_session_key(encrypted_session_key)
        signature_valid = receiver_km.verify_signature(
            handshake_message,
            signature,
            sender_km.public_key
        )
        session_key_valid = session_key == decrypted_session_key
        
        # PHASE 6: Handshake confirmation
        print("  Phase 6: Handshake confirmation...")
        confirmation_message = b"Confirmation:SK_Exchange:Complete"
        receiver_signature = receiver_km.sign_data(confirmation_message)
        confirmation_valid = sender_km.verify_signature(
            confirmation_message,
            receiver_signature,
            receiver_km.public_key
        )
        
        passed = (
            signature_valid and 
            session_key_valid and 
            confirmation_valid
        )
        
        details = (
            f"✓ Phase 1: RSA-2048 key pairs generated\n"
            f"✓ Phase 2: Public keys exchanged (PEM format)\n"
            f"✓ Phase 3: Session key: {len(session_key)} bytes, encrypted: {len(encrypted_session_key)} bytes\n"
            f"✓ Phase 4: Handshake message signed by sender\n"
            f"✓ Phase 5: Receiver verified signature: {signature_valid}\n"
            f"✓ Phase 5: Session key decrypted correctly: {session_key_valid}\n"
            f"✓ Phase 6: Receiver confirmation signed: {confirmation_valid}\n"
            f"✓ Handshake complete: {passed}"
        )
        
        print_test_result(passed, details)
        return passed


def test_7_key_info_and_status():
    """Test key information retrieval."""
    print_test_header(7, "Key Information and Status")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        km = KeyManager(tmpdir)
        km.generate_key_pair()
        km.load_public_key_from_pem(km.get_public_key_pem(), as_peer=True)
        
        info = km.get_key_info()
        
        details = (
            f"✓ Private key loaded: {info['private_key_loaded']}\n"
            f"✓ Public key loaded: {info['public_key_loaded']}\n"
            f"✓ Peer public key loaded: {info['peer_public_key_loaded']}\n"
            f"✓ Key size: {info['key_size']} bits\n"
            f"✓ Hash algorithm: {info['hash_algorithm']}\n"
            f"✓ Encryption: {info['encryption_scheme']}\n"
            f"✓ Signatures: {info['signature_scheme']}"
        )
        
        all_loaded = (
            info['private_key_loaded'] and 
            info['public_key_loaded'] and 
            info['peer_public_key_loaded']
        )
        
        print_test_result(all_loaded, details)
        return all_loaded


def run_all_tests():
    """Run all RSA key management tests."""
    print("\n" + "█" * 70)
    print("RSA KEY MANAGEMENT SECURITY TESTS")
    print("█" * 70)
    
    tests = [
        test_1_rsa_key_generation,
        test_2_key_saving_and_loading,
        test_3_rsa_encryption_decryption,
        test_4_digital_signatures,
        test_5_session_key_management,
        test_6_complete_key_exchange_handshake,
        test_7_key_info_and_status,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"\n❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    for i, result in enumerate(results, 1):
        status = "✅" if result else "❌"
        print(f"{status} Test {i}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n" + "█" * 70)
        print("✅ ALL RSA KEY MANAGEMENT TESTS PASSED")
        print("█" * 70 + "\n")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
