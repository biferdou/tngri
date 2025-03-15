"""
Cryptographic functions for the Tngri Password Manager.
"""

import base64
import logging
from typing import Union
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey

logger = logging.getLogger("tngri.crypto")

# Number of PBKDF2 iterations (higher is more secure but slower)
KDF_ITERATIONS = 200000


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from the password and salt using PBKDF2.
    
    Args:
        password: The password to derive key from
        salt: The salt for key derivation
        
    Returns:
        bytes: The derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_data(data: Union[str, bytes], key: bytes) -> bytes:
    """
    Encrypt data using the given key.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        
    Returns:
        bytes: Encrypted data
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    fernet = Fernet(key)
    return fernet.encrypt(data)


def decrypt_data(data: bytes, key: bytes) -> str:
    """
    Decrypt data using the given key.
    
    Args:
        data: Data to decrypt
        key: Encryption key
        
    Returns:
        str: Decrypted data as a string
        
    Raises:
        InvalidToken: If decryption fails
    """
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(data)
        return decrypted.decode('utf-8')
    except InvalidToken:
        logger.error("Invalid token - decryption failed")
        raise
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise


def generate_salt() -> bytes:
    """
    Generate a random salt for key derivation.
    
    Returns:
        bytes: Random salt
    """
    import os
    return os.urandom(16)


def verify_key(key: bytes, encrypted_data: bytes) -> bool:
    """
    Verify if a key can decrypt the given data.
    
    Args:
        key: Encryption key to verify
        encrypted_data: Encrypted data to test against
        
    Returns:
        bool: True if key can decrypt the data
    """
    try:
        fernet = Fernet(key)
        fernet.decrypt(encrypted_data)
        return True
    except (InvalidToken, InvalidKey):
        return False
    except Exception:
        return False