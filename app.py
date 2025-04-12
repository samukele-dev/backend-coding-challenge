from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from debug_code import broken_decrypt
import secrets
import base64
import time
import os

app = Flask(__name__)

# In-memory storage for messages (with timestamp for expiry)
MESSAGE_STORE = {}
# In-memory storage for user salts (for key derivation)
USER_SALTS = {}
# In-memory storage for user tokens (for basic authentication)
USER_TOKENS = {}
# Token expiry time in seconds (e.g., 1 hour)
TOKEN_EXPIRY_TIME = 3600
# Message expiry time in seconds (10 minutes)
MESSAGE_EXPIRY_TIME = 600

def generate_salt():
    # Generate a random 16-byte salt
    return os.urandom(16)

def derive_key(user_id, salt=None):
    # Use the provided salt, or retrieve the salt from USER_SALTS if not given
    if salt is None:
        salt = USER_SALTS.get(user_id)
        if salt is None:
            raise ValueError("Salt not found for user")  # Raise error if salt is not found

    # Set up PBKDF2HMAC to derive a key using SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 for hashing
        length=32,  # Key length (32 bytes)
        salt=salt,  # Salt for randomness
        iterations=100000,  # Number of iterations for added security
        backend=default_backend()  # Use the default cryptographic backend
    )

    # Derive the key from the user ID
    key = kdf.derive(user_id.encode('utf-8'))
    return key

def generate_token(user_id):
    # Generate a secure random token
    token = secrets.token_hex(32)
    expiry = time.time() + TOKEN_EXPIRY_TIME
    USER_TOKENS[token] = {'user_id': user_id, 'expiry': expiry}
    return token

def authenticate_user(token):
    if token in USER_TOKENS:
        token_data = USER_TOKENS[token]
        if token_data['expiry'] > time.time():
            return token_data['user_id']
        else:
            # Token expired, remove it
            del USER_TOKENS[token]
    return None

def encrypt_message(message, user_id):
    # Generate a unique salt for the user
    salt = generate_salt()

    # Store the salt associated with the user
    USER_SALTS[user_id] = salt

    # Derive an encryption key from the user ID and salt
    key = derive_key(user_id, salt)

    # Generate a random IV for AES encryption
    iv = os.urandom(16)

    # Set up AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create encryptor and padder
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Pad the message and encrypt it
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Combine salt, IV, and ciphertext, then base64 encode
    encrypted_payload = salt + iv + ciphertext
    return base64.b64encode(encrypted_payload).decode('utf-8')

def decrypt_message(encrypted_message_b64, user_id):
    try:
        # Decode the base64-encoded encrypted message
        encrypted_payload = base64.b64decode(encrypted_message_b64)

        # Extract the salt, IV, and ciphertext from the payload
        salt = encrypted_payload[:16]
        iv = encrypted_payload[16:32]
        ciphertext = encrypted_payload[32:]

        # Derive the key using the user ID and salt
        key = derive_key(user_id, salt)

        # Set up AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Create decryptor and decrypt the ciphertext
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

def cleanup_expired_messages():
    # Iterate through the message store and remove expired messages
    now = time.time()
    for user_id, messages in list(MESSAGE_STORE.items()):
        updated_messages = []
        for stored_message in messages:
            if 'timestamp' in stored_message and now - stored_message['timestamp'] < MESSAGE_EXPIRY_TIME:
                updated_messages.append(stored_message)
        MESSAGE_STORE[user_id] = updated_messages

@app.before_request
def before_request():
    # Clean up expired messages before each request
    cleanup_expired_messages()

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    user_id = data.get('userId')
    if not user_id:
        return jsonify({'error': 'Missing userId'}), 400
    # For simplicity, we're not handling password storage in this basic example
    # In a real application, you would hash and securely store passwords
    return jsonify({'status': 'User registered'}), 201

@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    user_id = data.get('userId')
    # In a real application, you would verify the password here
    if not user_id:
        return jsonify({'error': 'Missing userId'}), 400
    token = generate_token(user_id)
    return jsonify({'token': token}), 200

def require_auth():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    user_id = authenticate_user(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    return user_id

@app.route('/messages', methods=['POST'])
def store_message():
    user_id = require_auth()
    if not user_id:
        return  # require_auth already returned the error response

    # Get JSON data from the request
    data = request.get_json()
    message = data.get('message')

    # Check if message is provided
    if not message:
        return jsonify({'error': 'Missing message'}), 400

    # Encrypt the message for the user
    encrypted_message = encrypt_message(message, user_id)

    # Store the encrypted message under the user's ID with a timestamp
    if user_id not in MESSAGE_STORE:
        MESSAGE_STORE[user_id] = []
    MESSAGE_STORE[user_id].append({'encrypted_message': encrypted_message, 'timestamp': time.time()})

    # Return success response
    return jsonify({'status': 'Message stored successfully'}), 201

@app.route('/messages/<user_id>', methods=['GET'])
def get_messages(user_id):
    auth_user_id = require_auth()
    if not auth_user_id:
        return  # require_auth already returned the error response

    # Ensure the requested user_id matches the authenticated user's ID
    if auth_user_id != user_id:
        return jsonify({'error': 'Unauthorized to access these messages'}), 403

    # Check if the user has any messages stored
    if user_id not in MESSAGE_STORE:
        return jsonify({'messages': []}), 200

    decrypted_messages = []
    # Decrypt each message for the user
    for stored_message in MESSAGE_STORE.get(user_id, []):
        encrypted_message = stored_message.get('encrypted_message')
        if encrypted_message:
            decrypted = decrypt_message(encrypted_message, user_id)
            if decrypted.startswith("Decryption failed"):
                print(f"Warning: Could not decrypt message for user {user_id}: {decrypted}")
            else:
                decrypted_messages.append(decrypted)

    # Return the decrypted messages
    return jsonify({'messages': decrypted_messages}), 200

@app.route('/debug/decrypt', methods=['POST'])
def debug_decrypt_endpoint():
    # Get JSON data from the request for debugging
    data = request.get_json()
    encrypted_message = data.get('encrypted_message')
    user_id = data.get('userId')

    # Check if both encrypted_message and user_id are provided
    if not encrypted_message or not user_id:
        return jsonify({'error': 'Missing encrypted_message or userId'}), 400

    # Decrypt the message using a 'broken' decryption function for debugging
    decrypted = broken_decrypt(encrypted_message, user_id)
    return jsonify({'decrypted_message': decrypted}), 200

@app.route('/')
def index():
    return "Welcome to the Secure Messaging API!"

if __name__ == '__main__':
    # Run the Flask app in debug mode
    app.run(debug=True)