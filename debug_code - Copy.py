from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import base64

import os

# Store debug keys for users
USER_DEBUG_KEYS = {}

# Generate a random salt (16 bytes)
def generate_salt():
    return os.urandom(16)

# Derive a cryptographic key from the user's ID and salt using PBKDF2
def derive_key(user_id, salt):
    # Set up PBKDF2HMAC key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 hashing algorithm
        length=32,  # Key length (32 bytes)
        salt=salt,  # Salt for randomness
        iterations=100000,  # Number of iterations for security
        backend=default_backend()  # Use default cryptographic backend
    )
    # Derive the key from the user ID
    key = kdf.derive(user_id.encode('utf-8'))
    return key


# Broken decryption function (incorrect handling of salt and key derivation)
def broken_decrypt(encrypted_message_b64, user_id):
    try:
        # Decode the base64-encoded encrypted message
        encrypted_payload = base64.b64decode(encrypted_message_b64)
        
        # BROKEN: Incorrectly slice the payload, missing the salt
        iv = encrypted_payload[:16]  # Extract the IV (first 16 bytes)
        ciphertext = encrypted_payload[16:]  # Extract the ciphertext (remaining bytes)

        # BROKEN: Derive key without using the salt (it should be extracted from payload)
        salt = generate_salt()  # This generates a NEW salt (which is incorrect)
        key = derive_key(user_id, salt)  # Derive the key using the user ID and the new salt

        # Set up AES cipher in CBC mode with the derived key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # Decrypt the ciphertext
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted message
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Return the decrypted message as a string
        return plaintext.decode('utf-8')
    except Exception as e:
        # Return error message if decryption fails
        return f"Decryption failed: {e}"


# Test case to reproduce the problem with broken decryption
def test_broken_decrypt():
    user_id = "test_user"  # Example user ID
    salt = generate_salt()  # Generate a random salt
    key = derive_key(user_id, salt)  # Derive the key using the user ID and salt
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    plaintext = "This is a secret message for debugging."  # Message to encrypt
    
    # Apply padding to the plaintext to make it a multiple of the AES block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Set up AES cipher in CBC mode with the derived key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Combine salt, IV, and ciphertext into a single encrypted payload
    encrypted_payload = salt + iv + ciphertext
    
    # Base64 encode the encrypted payload to prepare for transmission
    encrypted_message_b64 = base64.b64encode(encrypted_payload).decode('utf-8')

    # Attempt to decrypt the message using the broken decryption function
    decrypted_message = broken_decrypt(encrypted_message_b64, user_id)
    print(f"Test with broken decrypt: {decrypted_message}")

    # Assert that decryption fails or the decrypted message doesn't match the original plaintext
    assert "Decryption failed" in decrypted_message or plaintext != decrypted_message


# Fixed decrypt function (corrects issues in broken_decrypt)
def fixed_decrypt(encrypted_message_b64, user_id):
    try:
        # Decode the base64-encoded encrypted message
        encrypted_payload = base64.b64decode(encrypted_message_b64)
        
        # Extract salt, IV, and ciphertext from the payload
        salt = encrypted_payload[:16]  # First 16 bytes: salt
        iv = encrypted_payload[16:32]  # Next 16 bytes: IV
        ciphertext = encrypted_payload[32:]  # Remaining bytes: ciphertext
        
        # Derive the key using the user ID and extracted salt
        key = derive_key(user_id, salt)

        # Set up AES cipher in CBC mode for decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted message
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Return the decrypted plaintext message
        return plaintext.decode('utf-8')
    except Exception as e:
        # Return error message if decryption fails
        return f"Decryption failed: {e}"


# Test case for the fixed decrypt function
def test_fixed_decrypt():
    user_id = "test_user"  # Example user ID
    salt = generate_salt()  # Generate a random salt
    key = derive_key(user_id, salt)  # Derive the key using the user ID and salt
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    plaintext = "This is a secret message for testing the fix."  # Message to encrypt
    
    # Apply padding to the plaintext to match the AES block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Set up AES cipher in CBC mode with the derived key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Combine salt, IV, and ciphertext into a single encrypted payload
    encrypted_payload = salt + iv + ciphertext
    
    # Base64 encode the encrypted payload to prepare for transmission
    encrypted_message_b64 = base64.b64encode(encrypted_payload).decode('utf-8')

    # Decrypt the message using the fixed decryption function
    decrypted_message = fixed_decrypt(encrypted_message_b64, user_id)
    print(f"Test with fixed decrypt: {decrypted_message}")

    # Assert that the decrypted message matches the original plaintext
    assert plaintext == decrypted_message

if __name__ == "__main__":
    # Run both tests: broken decrypt and fixed decrypt
    test_broken_decrypt()
    test_fixed_decrypt()

