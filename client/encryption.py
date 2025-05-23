import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def hash_password(password):
    """Hash a password for storing in the database."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verify a stored password hash against the provided password."""
    return stored_hash == hash_password(password)

def derive_key(password):
    """Derive a 32-byte (256-bit) encryption key from a password."""
    # Use SHA-256 to generate a fixed-length key
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message, key):
    """Encrypt a message using AES-CBC.
    
    Args:
        message: The plaintext message as a string
        key: The encryption key as bytes
        
    Returns:
        Base64-encoded encrypted message
    """
    # If key is a string, convert to bytes
    if isinstance(key, str):
        key = derive_key(key)
    
    # Make sure we have a bytes object for message
    if isinstance(message, str):
        message = message.encode()
    
    # Initialize cipher with key in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    
    # Pad the message to be a multiple of block size
    padded_message = pad(message, AES.block_size)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(padded_message)
    
    # Combine IV and ciphertext for sending
    encrypted_data = cipher.iv + ciphertext
    
    # Base64 encode for easy transmission
    return base64.b64encode(encrypted_data)

def decrypt_message(encrypted_data, key):
    """Decrypt a message using AES-CBC.
    
    Args:
        encrypted_data: Base64-encoded encrypted message
        key: The encryption key as bytes
        
    Returns:
        Decrypted message as a string
    """
    # If key is a string, convert to bytes
    if isinstance(key, str):
        key = derive_key(key)
    
    # If encrypted_data is a string, decode it
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    
    # Base64 decode
    try:
        encrypted_data = base64.b64decode(encrypted_data)
    except:
        # If it's not base64 encoded, use as is
        pass
    
    # Extract IV (first 16 bytes)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    # Initialize cipher with key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Return as string
    return decrypted_message.decode()