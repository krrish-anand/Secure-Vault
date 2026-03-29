import struct

VAULT_FILE = "MyVaultFile.vault"
INDEX_OFFSET_SIZE = 8
SALT_SIZE = 16

with open(VAULT_FILE, "rb") as vault_file:
    # Read the salt (first 16 bytes)
    vault_file.seek(0)
    salt = vault_file.read(SALT_SIZE)
    print(f"Salt: {salt.hex()}")

    # Read the last 8 bytes (index offset)
    vault_file.seek(-INDEX_OFFSET_SIZE, 2)
    index_offset_bytes = vault_file.read(INDEX_OFFSET_SIZE)
    try:
        index_offset = struct.unpack(">Q", index_offset_bytes)[0]
        print(f"Index Offset: {index_offset}")
    except Exception as e:
        print(f"Error reading index offset: {e}")
