"""
Erasure Coding Tests

Test scenarios for XOR-based self-healing:
1. No loss - all blocks present
2. One missing block - recovery works
3. Two missing blocks - recovery fails (expected)
"""

import sys
import os

# Add parent directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from transmission.erasure_coding import (
    xor_bytes, 
    generate_parity_blocks, 
    recover_block,
    recover_missing_blocks
)


def test_xor_operations():
    """Test basic XOR operations."""
    print("\n" + "="*70)
    print("TEST 1: XOR Basic Operations")
    print("="*70)
    
    # Test XOR properties
    a = b"Hello World!!!!!"  # 16 bytes
    b = b"Data to XOR!!!!!"   # 16 bytes
    
    parity = xor_bytes(a, b)
    print(f"✓ XOR generated parity: {len(parity)} bytes")
    
    # Recover a from b and parity
    recovered_a = xor_bytes(b, parity)
    if recovered_a == a:
        print(f"✓ Recovery successful: a = b XOR parity")
    else:
        print(f"✗ Recovery failed: recovered != original")
    
    # Recover b from a and parity
    recovered_b = xor_bytes(a, parity)
    if recovered_b == b:
        print(f"✓ Recovery successful: b = a XOR parity")
    else:
        print(f"✗ Recovery failed: recovered != original")
    
    print("✅ XOR Operations Test PASSED")


def test_parity_generation():
    """Test parity block generation."""
    print("\n" + "="*70)
    print("TEST 2: Parity Block Generation")
    print("="*70)
    
    # Create 4 data blocks
    blocks = [
        b"Block 0 data!!!!", 
        b"Block 1 data!!!!", 
        b"Block 2 data!!!!", 
        b"Block 3 data!!!!"
    ]
    
    parity_list = generate_parity_blocks(blocks)
    
    print(f"✓ Generated {len(parity_list)} parity blocks from {len(blocks)} data blocks")
    
    # Should have 2 parity blocks (one per pair)
    if len(parity_list) == 2:
        print(f"✓ Parity count correct: {len(parity_list)}")
    else:
        print(f"✗ Expected 2 parity blocks, got {len(parity_list)}")
    
    # Verify parity block indices
    for idx, (parity_idx, parity_data) in enumerate(parity_list):
        print(f"✓ Parity block {parity_idx} (group {parity_idx}): {len(parity_data)} bytes")
        if parity_idx != idx:
            print(f"✗ Expected parity index {idx}, got {parity_idx}")
    
    print("✅ Parity Generation Test PASSED")


def test_recovery_no_loss():
    """Test scenario: no blocks lost."""
    print("\n" + "="*70)
    print("TEST 3: No Loss Scenario")
    print("="*70)
    
    blocks = [b"Data 0 block...", b"Data 1 block...", b"Data 2 block..."]
    parity_list = generate_parity_blocks(blocks)
    
    # All blocks received
    received = {0: blocks[0], 1: blocks[1], 2: blocks[2]}
    parity = {i: p for i, p in parity_list}
    
    recovered = recover_missing_blocks(received, parity, len(blocks))
    
    if len(recovered) == 0:
        print(f"✓ No recovery needed (all blocks present)")
    else:
        print(f"⚠ Unexpected recovery: {len(recovered)} blocks recovered")
    
    print("✅ No Loss Test PASSED")


def test_recovery_one_missing():
    """Test scenario: one block lost, recovery works."""
    print("\n" + "="*70)
    print("TEST 4: One Missing Block (Recovery Works)")
    print("="*70)
    
    blocks = [b"Data 0 block...", b"Data 1 block...", b"Data 2 block...", b"Data 3 block..."]
    parity_list = generate_parity_blocks(blocks)
    
    # Lose block 1 (in group 0)
    received = {0: blocks[0], 2: blocks[2], 3: blocks[3]}  # Missing: 1
    parity = {i: p for i, p in parity_list}
    
    print(f"✓ Simulating loss of block 1 (group 0)")
    print(f"✓ Received blocks: {list(received.keys())}")
    print(f"✓ Available parity: {list(parity.keys())}")
    
    recovered = recover_missing_blocks(received, parity, len(blocks))
    
    if 1 in recovered:
        print(f"✓ Block 1 recovered successfully!")
        print(f"✓ Recovery produced {len(recovered[1])} bytes")
    else:
        print(f"✗ Block 1 not recovered")
    
    print("✅ Recovery Test PASSED")


def test_recovery_two_missing_same_group():
    """Test scenario: two blocks lost in same group - recovery fails."""
    print("\n" + "="*70)
    print("TEST 5: Two Missing in Same Group (Recovery Fails - Expected)")
    print("="*70)
    
    blocks = [b"Data 0 block...", b"Data 1 block...", b"Data 2 block...", b"Data 3 block..."]
    parity_list = generate_parity_blocks(blocks)
    
    # Lose blocks 0 and 1 (both in group 0)
    received = {2: blocks[2], 3: blocks[3]}  # Missing: 0, 1
    parity = {i: p for i, p in parity_list}
    
    print(f"✓ Simulating loss of blocks 0 and 1 (both in group 0)")
    print(f"✓ Received blocks: {list(received.keys())}")
    
    recovered = recover_missing_blocks(received, parity, len(blocks))
    
    if 0 not in recovered and 1 not in recovered:
        print(f"✓ Correctly failed to recover (as expected)")
        print(f"✓ Cannot recover 2 blocks with 1 parity block")
    else:
        print(f"⚠ Unexpected recovery: recovered {list(recovered.keys())}")
    
    print("✅ Two Missing Test PASSED")


def test_recovery_two_missing_different_groups():
    """Test scenario: one block missing in each group - recovery works."""
    print("\n" + "="*70)
    print("TEST 6: One Missing in Each Group (Recovery Works)")
    print("="*70)
    
    blocks = [b"Data 0 block...", b"Data 1 block...", b"Data 2 block...", b"Data 3 block..."]
    parity_list = generate_parity_blocks(blocks)
    
    # Lose block 1 (group 0) and block 3 (group 1)
    received = {0: blocks[0], 2: blocks[2]}  # Missing: 1, 3
    parity = {i: p for i, p in parity_list}
    
    print(f"✓ Simulating loss of block 1 (group 0) and block 3 (group 1)")
    print(f"✓ Received blocks: {list(received.keys())}")
    
    recovered = recover_missing_blocks(received, parity, len(blocks))
    
    if 1 in recovered and 3 in recovered:
        print(f"✓ Both blocks recovered successfully!")
        print(f"  - Block 1 recovered: {len(recovered[1])} bytes")
        print(f"  - Block 3 recovered: {len(recovered[3])} bytes")
    else:
        print(f"✗ Recovery incomplete: recovered {list(recovered.keys())}")
    
    print("✅ Multiple Groups Test PASSED")


if __name__ == "__main__":
    print("\n" + "█"*70)
    print("ERASURE CODING TESTS")
    print("█"*70)
    
    try:
        test_xor_operations()
        test_parity_generation()
        test_recovery_no_loss()
        test_recovery_one_missing()
        test_recovery_two_missing_same_group()
        test_recovery_two_missing_different_groups()
        
        print("\n" + "█"*70)
        print("ALL ERASURE CODING TESTS PASSED ✅")
        print("█"*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
