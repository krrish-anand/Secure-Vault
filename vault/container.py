import os
import struct
import json

from vault.authentication import generate_salt, derive_key
from vault.encryption import encrypt_data, decrypt_data
from vault.file_integrity import calculate_hash

VAULT_EXTENSION = ".vault"
INDEX_OFFSET_SIZE = 8           # 8 bytes to store the index offset at the end
CHUNK_SIZE_HEADER = 8           # Each chunk has an 8-byte length header
SALT_SIZE = 16                  # 16 bytes salt
AES_KEY_SIZE = 32               # 256 bits

class PartialReadVault:
    """
    A vault that uses partial reads for each file chunk.
    The index is stored at offset=16 in a brand-new vault, then appended as needed.
    The final 8 bytes contain the integer offset where the index starts.
    """

    def __init__(self):
        self.vault_path = None
        self.master_key = None
        self.index_data = None  # {"files": {filename: {offset, chunk_size, plaintext_size, hash}}}
        self.is_unlocked = False

    # -------------------------------------------------------------------------
    # CREATE VAULT
    # -------------------------------------------------------------------------
    def create_vault(self, vault_path: str, password: str):
        """
        Creates a brand-new vault:
         - Writes salt at offset=0
         - Writes encrypted index at offset=16
         - Writes '16' at the final 8 bytes to indicate index_offset=16
        """
        if not vault_path.endswith(VAULT_EXTENSION):
            vault_path += VAULT_EXTENSION

        if os.path.exists(vault_path):
            raise FileExistsError("Vault file already exists.")

        self.vault_path = vault_path

        # Create parent directory if it doesn't exist
        parent_dir = os.path.dirname(vault_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        # 1) Generate salt & master key
        salt = generate_salt(SALT_SIZE)
        self.master_key = derive_key(password, salt)

        # 2) Initialize an empty index
        self.index_data = {"files": {}}

        with open(self.vault_path, "wb") as vault_file:
            # Write the 16-byte salt at offset=0
            vault_file.write(salt)

            # Decide that for a brand-new vault, index_offset=16
            index_offset = 16

            # Seek to offset=16
            vault_file.seek(index_offset, os.SEEK_SET)

            # Encrypt the empty index and write it here
            encrypted_index = self._encrypt_index()
            vault_file.write(encrypted_index)

            # Now we're at offset = 16 + len(encrypted_index)
            final_offset = vault_file.tell()

            # Finally, write the '16' offset in the last 8 bytes
            # This ensures unlock_vault can read it
            vault_file.write(struct.pack(">Q", index_offset))

        self.is_unlocked = True
        print(f"Vault created at {vault_path} (index_offset=16)")

    # -------------------------------------------------------------------------
    # UNLOCK VAULT
    # -------------------------------------------------------------------------
    def unlock_vault(self, vault_path: str, password: str):
        """
        Reads the salt from offset=0..15, and the last 8 bytes for index_offset,
        then decrypts the index from index_offset..EOF-8
        """
        if not os.path.exists(vault_path):
            raise FileNotFoundError("Vault file not found.")

        self.vault_path = vault_path

        with open(self.vault_path, "rb") as vault_file:
            # 1) Read salt
            salt = vault_file.read(SALT_SIZE)
            print(f"DEBUG: Salt: {salt.hex()}")

            # 2) Read the final 8 bytes to get the offset
            vault_file.seek(-INDEX_OFFSET_SIZE, os.SEEK_END)
            offset_bytes = vault_file.read(INDEX_OFFSET_SIZE)
            index_offset = struct.unpack(">Q", offset_bytes)[0]
            print(f"DEBUG: Index Offset: {index_offset}")

            # 3) Derive master key
            self.master_key = derive_key(password, salt)
            print(f"DEBUG: Master Key: {self.master_key.hex()}")

            # 4) Figure out how many bytes the encrypted index occupies:
            file_size = vault_file.tell()  # i.e., total size is final offset
            # Actually, vault_file.tell() is at end, so file_size = offset of EOF

            # The encrypted index is from index_offset..(file_size - 8)
            enc_index_size = file_size - INDEX_OFFSET_SIZE - index_offset
            if enc_index_size < 0:
                raise ValueError("Invalid index offset, vault file appears corrupted.")

            # 5) Read the encrypted index
            vault_file.seek(index_offset, os.SEEK_SET)
            encrypted_index = vault_file.read(enc_index_size)
            print(f"DEBUG: Encrypted Index (hex): {encrypted_index.hex()}")

        # 6) Decrypt the index
        try:
            index_plaintext = decrypt_data(self.master_key, encrypted_index)
            print(f"DEBUG: Index Plaintext: {index_plaintext.decode('utf-8')}")
            self.index_data = json.loads(index_plaintext.decode("utf-8"))
            self.is_unlocked = True
        except Exception as e:
            raise ValueError(f"Incorrect password or corrupted vault: {e}")

    # -------------------------------------------------------------------------
    # LOCK VAULT
    # -------------------------------------------------------------------------
    def lock_vault(self):
        """
        Clears sensitive data from memory.
        """
        self.master_key = None
        self.index_data = None
        self.is_unlocked = False
        self.vault_path = None

    # -------------------------------------------------------------------------
    # ADD FILE
    # -------------------------------------------------------------------------
    def add_file(self, file_path: str):
        """
        Appends a file chunk in front of the existing index,
        then moves the index to the new end, and updates the final offset.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault must be unlocked before adding files.")

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Compute file hash & size
        file_hash = calculate_hash(plaintext)
        plaintext_size = len(plaintext)

        # Encrypt
        encrypted_data = encrypt_data(self.master_key, plaintext)
        chunk_length = len(encrypted_data)

        with open(self.vault_path, "rb+") as vault_file:
            # 1) Read the final 8 bytes => old index_offset
            vault_file.seek(-INDEX_OFFSET_SIZE, os.SEEK_END)
            offset_bytes = vault_file.read(INDEX_OFFSET_SIZE)
            old_index_offset = struct.unpack(">Q", offset_bytes)[0]

            # 2) The new file chunk will be placed at old_index_offset
            new_chunk_offset = old_index_offset

            # 3) Write the chunk size + encrypted data at new_chunk_offset
            vault_file.seek(new_chunk_offset)
            vault_file.write(struct.pack(">Q", chunk_length))  # chunk size
            vault_file.write(encrypted_data)

            # 4) The new index offset is new_chunk_offset + chunk_size + 8
            updated_index_offset = new_chunk_offset + CHUNK_SIZE_HEADER + chunk_length

            # 5) Update our in-memory index
            self.index_data["files"][filename] = {
                "offset": new_chunk_offset,
                "chunk_size": CHUNK_SIZE_HEADER + chunk_length,
                "plaintext_size": plaintext_size,
                "hash": file_hash
            }

            # 6) Rewrite the updated index at updated_index_offset
            vault_file.seek(updated_index_offset)
            new_encrypted_index = self._encrypt_index()
            vault_file.write(new_encrypted_index)

            # 7) Finally, update the last 8 bytes with updated_index_offset
            vault_file.write(struct.pack(">Q", updated_index_offset))

    # -------------------------------------------------------------------------
    # EXTRACT FILE
    # -------------------------------------------------------------------------
    def extract_file(self, filename: str, output_path: str):
        """
        Extracts only the chunk for 'filename'.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault must be unlocked before extracting files.")

        if filename not in self.index_data["files"]:
            raise FileNotFoundError(f"File '{filename}' not found in vault index.")

        file_info = self.index_data["files"][filename]
        chunk_offset = file_info["offset"]
        chunk_size = file_info["chunk_size"]

        with open(self.vault_path, "rb") as vault_file:
            # Read chunk size
            vault_file.seek(chunk_offset)
            declared_chunk_size = struct.unpack(">Q", vault_file.read(8))[0]

            if declared_chunk_size + CHUNK_SIZE_HEADER != chunk_size:
                raise ValueError("Mismatch in chunk size. Possibly corrupted vault.")

            # Read encrypted data
            encrypted_data = vault_file.read(declared_chunk_size)

        # Decrypt
        plaintext = decrypt_data(self.master_key, encrypted_data)

        # Verify hash
        if calculate_hash(plaintext) != file_info["hash"]:
            raise ValueError("File integrity check failed. Possibly corrupted data.")

        # Write to disk
        with open(output_path, "wb") as out_f:
            out_f.write(plaintext)

    # -------------------------------------------------------------------------
    # REMOVE FILE
    # -------------------------------------------------------------------------
    def remove_file(self, filename: str):
        """
        Removes 'filename' from the vault index so it's no longer accessible.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault must be unlocked to remove files.")

        if filename not in self.index_data["files"]:
            raise FileNotFoundError(f"No such file '{filename}' in vault.")

        del self.index_data["files"][filename]
        self._save_index()

    # -------------------------------------------------------------------------
    # LIST FILES
    # -------------------------------------------------------------------------
    def list_files(self):
        """
        Returns a dict of { filename: metadata } from the in-memory index.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault is locked.")
        return self.index_data["files"]

    # -------------------------------------------------------------------------
    # INTERNAL HELPERS
    # -------------------------------------------------------------------------
    def _save_index(self):
        """
        Re-encrypt and rewrite the index in the file, updating the final offset.
        """
        if not self.is_unlocked or not self.vault_path:
            return

        with open(self.vault_path, "rb+") as vault_file:
            # 1) Read the old offset
            vault_file.seek(-INDEX_OFFSET_SIZE, os.SEEK_END)
            old_index_offset = struct.unpack(">Q", vault_file.read(INDEX_OFFSET_SIZE))[0]

            # 2) Our new encrypted index will go exactly where the old index started
            vault_file.seek(old_index_offset)
            new_encrypted_index = self._encrypt_index()
            vault_file.write(new_encrypted_index)

            # 3) Update offset
            new_index_offset = vault_file.tell()

            # 4) Write the new offset in the last 8 bytes
            vault_file.write(struct.pack(">Q", new_index_offset))

    def _encrypt_index(self) -> bytes:
        """
        Encrypts the in-memory index (JSON) with the master key (AES-GCM).
        """
        if self.index_data is None:
            raise RuntimeError("Index not loaded or unlocked.")

        index_str = json.dumps(self.index_data)
        index_bytes = index_str.encode("utf-8")
        return encrypt_data(self.master_key, index_bytes)
