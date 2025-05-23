import hashlib
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def hash_password(password):
    """Hash a password for storing in the database using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    """Verify a password against its stored hash."""
    return hash_password(password) == stored_hash

def derive_key(password):
    """Derive a 32-byte (256-bit) encryption key from a password."""
    return hashlib.sha256(password.encode()).digest()

def generate_aes_key():
    """Generate a random 32-byte AES key."""
    return os.urandom(32)

def encrypt_message(message, key):
    """
    Encrypt a message using AES-CBC encryption.
    
    Args:
        message: The plaintext message (string or bytes)
        key: The encryption key (bytes or string)
        
    Returns:
        Base64-encoded encrypted message as bytes
    """
    # Ensure key is bytes
    if isinstance(key, str):
        key = derive_key(key)
    
    # Ensure message is bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate random IV
    iv = os.urandom(AES.block_size)
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad message to block size
    padded_message = pad(message, AES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_message)
    
    # Combine IV and ciphertext
    encrypted_data = iv + ciphertext
    
    # Return base64 encoded
    return base64.b64encode(encrypted_data)

def decrypt_message(encrypted_data, key):
    """
    Decrypt a message using AES-CBC decryption.
    
    Args:
        encrypted_data: Base64-encoded encrypted message (string or bytes)
        key: The encryption key (bytes or string)
        
    Returns:
        Decrypted message as string
    """
    # Ensure key is bytes
    if isinstance(key, str):
        key = derive_key(key)
    
    # Handle input format
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    
    # Base64 decode
    try:
        encrypted_data = base64.b64decode(encrypted_data)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {e}")
    
    # Extract IV and ciphertext
    if len(encrypted_data) < AES.block_size:
        raise ValueError("Encrypted data too short")
    
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt
    try:
        decrypted_padded = cipher.decrypt(ciphertext)
        # Unpad
        decrypted_message = unpad(decrypted_padded, AES.block_size)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

# Additional utility functions
def secure_compare(a, b):
    """Securely compare two strings to prevent timing attacks."""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0