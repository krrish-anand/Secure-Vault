import sys
from vault.container import PartialReadVault
from transmission.transmission_manager import TransmissionManager


def print_usage():
    """Print usage information for all commands."""
    print("Secure Vault - File Management & Secure Transmission")
    print("\n" + "="*70)
    print("VAULT COMMANDS (Local Encryption):")
    print("="*70)
    print("  python main.py create <vault_path> <password>")
    print("  python main.py open <vault_path> <password>")
    print("  python main.py add <vault_path> <password> <file_to_add>")
    print("  python main.py extract <vault_path> <password> <filename_in_vault> <output_path>")
    print("  python main.py list <vault_path> <password>")
    print("  python main.py remove <vault_path> <password> <filename_in_vault>")
    
    print("\n" + "="*70)
    print("TRANSMISSION COMMANDS (Network-Enabled):")
    print("="*70)
    print("  python main.py transmit-send <file_path> <receiver_host> <receiver_port> [password]")
    print("  python main.py transmit-receive <listen_port> <output_dir> [password]")
    print("  python main.py transmit-demo")
    print("\n" + "="*70)


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()
    vault = PartialReadVault()

    if command == "create":
        if len(sys.argv) < 4:
            print("Usage: python main.py create <vault_path> <password>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        vault.create_vault(vault_path, password)
        print(f"Vault created at {vault_path}")

    elif command == "open":
        if len(sys.argv) < 4:
            print("Usage: python main.py open <vault_path> <password>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        vault.unlock_vault(vault_path, password)
        print("Vault unlocked. Files in vault:")
        for fname in vault.list_files():
            print(f" - {fname}")

    elif command == "add":
        if len(sys.argv) < 5:
            print("Usage: python main.py add <vault_path> <password> <file_to_add>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        file_to_add = sys.argv[4]

        vault.unlock_vault(vault_path, password)
        vault.add_file(file_to_add)
        print(f"Added {file_to_add} to {vault_path}")

    elif command == "extract":
        if len(sys.argv) < 6:
            print("Usage: python main.py extract <vault_path> <password> <filename_in_vault> <output_path>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        filename_in_vault = sys.argv[4]
        output_path = sys.argv[5]

        vault.unlock_vault(vault_path, password)
        vault.extract_file(filename_in_vault, output_path)
        print(f"Extracted {filename_in_vault} to {output_path}")

    elif command == "list":
        if len(sys.argv) < 4:
            print("Usage: python main.py list <vault_path> <password>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]

        vault.unlock_vault(vault_path, password)
        files = vault.list_files()
        if files:
            print("Files in vault:")
            for fname, metadata in files.items():
                print(f" - {fname} (size: {metadata['plaintext_size']} bytes)")
        else:
            print("No files in the vault.")

    elif command == "remove":
        if len(sys.argv) < 5:
            print("Usage: python main.py remove <vault_path> <password> <filename_in_vault>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        filename_in_vault = sys.argv[4]

        vault.unlock_vault(vault_path, password)
        vault.remove_file(filename_in_vault)
        print(f"Removed {filename_in_vault} from vault")

    elif command == "transmit-send":
        """Send a file via secure transmission."""
        if len(sys.argv) < 5:
            print("Usage: python main.py transmit-send <file_path> <receiver_host> <receiver_port> [password]")
            sys.exit(1)
        
        file_path = sys.argv[2]
        receiver_host = sys.argv[3]
        receiver_port = int(sys.argv[4])
        password = sys.argv[5] if len(sys.argv) > 5 else "default_password"
        
        print(f"\n{'='*70}")
        print(f"SECURE TRANSMISSION - SENDER MODE")
        print(f"{'='*70}")
        print(f"File: {file_path}")
        print(f"Destination: {receiver_host}:{receiver_port}")
        
        manager = TransmissionManager(vault_password=password)
        success = manager.send_file(file_path, receiver_host, receiver_port)
        
        if success:
            print("\n✅ File transmission completed successfully!")
            sys.exit(0)
        else:
            print("\n❌ File transmission failed!")
            sys.exit(1)

    elif command == "transmit-receive":
        """Receive a file via secure transmission."""
        if len(sys.argv) < 4:
            print("Usage: python main.py transmit-receive <listen_port> <output_dir> [password]")
            sys.exit(1)
        
        listen_port = int(sys.argv[2])
        output_dir = sys.argv[3]
        password = sys.argv[4] if len(sys.argv) > 4 else "default_password"
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            print(f"✓ Created output directory: {output_dir}")
        
        output_file = os.path.join(output_dir, f"received_file_{int(time.time())}.bin")
        
        print(f"\n{'='*70}")
        print(f"SECURE TRANSMISSION - RECEIVER MODE")
        print(f"{'='*70}")
        print(f"Listen port: {listen_port}")
        print(f"Output directory: {output_dir}")
        
        manager = TransmissionManager(vault_password=password)
        success = manager.receive_file(listen_port, output_file, expected_blocks=None)
        
        if success:
            print(f"\n✅ File reception completed successfully!")
            print(f"File saved to: {output_file}")
            sys.exit(0)
        else:
            print(f"\n❌ File reception failed!")
            sys.exit(1)

    elif command == "transmit-demo":
        """Demo of transmission system (requires manual setup of sender/receiver)."""
        print(f"\n{'='*70}")
        print(f"SECURE TRANSMISSION - DEMO")
        print(f"{'='*70}")
        print("\nTo demo the transmission system:")
        print("\n1. Terminal 1 (RECEIVER) - Listen on port 5000:")
        print("   python main.py transmit-receive 5000 ./received/")
        print("\n2. Terminal 2 (SENDER) - Send file to localhost:5000:")
        print("   python main.py transmit-send myfile.txt 127.0.0.1 5000")
        print("\nThe receiver will listen for incoming blocks and reconstruct the file.")
        print("Make sure both terminals have the same password (default: 'default_password')")

    else:
        print(f"Unknown command: {command}")
        print("\nUse 'python main.py' with no arguments to see all available commands.")

if __name__ == "__main__":
    import os
    import time
    main()
