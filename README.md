# secure-vault


Secure Vault is a Python-based file management system designed for securely storing, encrypting, and managing files. It uses advanced encryption techniques to protect your data and provides an easy-to-use graphical interface for interaction.

## Features

-> **Create Encrypted Vaults:** Users can create vaults with a password to securely store files.

![Kapture 2025-02-04 at 03 24 13 03 31 02](https://github.com/user-attachments/assets/9e07b2a7-ca5d-4a84-bb9b-8103c0d324b2)

-> **File Encryption:** Files are encrypted when added to the vault, ensuring their security.

![Kapture 2025-02-04 at 01 48 20](https://github.com/user-attachments/assets/55431aeb-fbc0-4d2a-a0ab-c50d723c7809)

-> **File Management:** Add, list, remove, and extract files from the vault through the graphical interface.

![Kapture 2025-02-04 at 01 44 02](https://github.com/user-attachments/assets/b8c53b6c-cbb2-4acb-a0f4-fc779cbc951c)

-> **Integrity Check:** Ensures that files are not tampered with inside the vault.

![Kapture 2025-02-04 at 03 32 56](https://github.com/user-attachments/assets/9ad0fbc6-416f-4feb-8164-8c5d7a70852a)

-> **Metadata Handling:** Securely stores file metadata, such as file offsets, sizes, and hashes.

-> **Padding for Security:** Vault files are padded to hide their true size, improving security.

-> **Graphical User Interface (GUI):** Built with Tkinter, the GUI provides a user-friendly experience.


## How to Run

Follow these steps to set up and run the Secure Vault project:

### 1. Clone the Repository
```bash
git clone https://github.com/selimyilbas/secure-vault.git
cd secure-vault
```


### 2. Set Up a Virtual Environment

Create a virtual environment to manage dependencies:

**On Windows:**
```
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
Install the required Python libraries:

```
pip install pillow
pip install pycryptodome
```

**Note:** The project requires `pycryptodome` (not `cryptography`) for AES encryption.

### 4. Run the Application
   
Start the Secure Vault GUI:

**On Windows:**
```
python gui.py
```

**On macOS/Linux:**
```
python3 gui.py
```

## Usage

-> **Create a Vault:** Enter a vault path and password, then click "Create Vault."

-> **Open a Vault:** Use the same vault path and password to access an existing vault.

-> **Add Files:** Add files to the vault for encryption.

-> **Extract Files:** Extract encrypted files back to their original state.

-> **Lock Vault:** Securely lock the vault when you're done.

-> **Exit the Application**

-> Simply close the GUI window to exit.





