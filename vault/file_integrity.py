import hashlib

def calculate_hash(content: bytes) -> str:
    """
    Returns the SHA-256 hex digest of the given content.
    """
    return hashlib.sha256(content).hexdigest()
