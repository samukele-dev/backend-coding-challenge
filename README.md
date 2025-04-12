# Secure Messaging API - Backend Coding Challenge

## Design Write-Up

**Encryption Method and Mode:**

I have chosen AES-256 in Cipher Block Chaining (CBC) mode for encrypting messages. AES (Advanced Encryption Standard) is a widely trusted and robust symmetric encryption algorithm, and using a 256-bit key length provides a high level of security against brute-force attacks. CBC mode is a common mode of operation for block ciphers. It works by XORing each plaintext block with the previous ciphertext block before encryption. This introduces dependency between blocks, making identical plaintext blocks produce different ciphertext blocks, thus enhancing security. An Initialization Vector (IV) is crucial in CBC mode to ensure that the encryption of the same plaintext with the same key results in different ciphertexts across multiple encryptions.

**Ensuring Only the Original User Can Access Messages:**

To ensure that only the original user can decrypt and retrieve their messages, the encryption key is derived uniquely for each user based on their `userId`. This is achieved using PBKDF2HMAC (Password-Based Key Derivation Function 2 with HMAC-SHA256). When a user sends their first message, a unique random salt is generated and associated with their `userId`. This salt is then used along with the `userId` as input to PBKDF2HMAC to derive a strong 256-bit encryption key. The generated salt is stored (in this in-memory implementation, in the `USER_SALTS` dictionary) and is also prepended to the encrypted payload before being stored. During decryption, the salt is extracted from the stored encrypted message, and the same PBKDF2HMAC process is used with the user's `userId` and the extracted salt to regenerate the exact same decryption key. Without knowing the correct `userId` and the associated salt (which is part of their encrypted messages), it is computationally infeasible to derive the correct decryption key.

**How the IV is Stored and Later Extracted:**

For each message encrypted, a fresh, cryptographically secure 16-byte Initialization Vector (IV) is generated. To ensure it can be used for decryption, the IV is embedded within the encrypted payload. The structure of the stored encrypted message (after base64 encoding) is as follows: `salt (16 bytes) + IV (16 bytes) + ciphertext`. During the decryption process:

1.  The base64 encoded message is decoded.
2.  The first 16 bytes of the decoded payload are extracted as the salt.
3.  The next 16 bytes are extracted as the IV.
4.  The remaining bytes are treated as the actual ciphertext.

These extracted components (salt, IV, and ciphertext) are then used in the AES-256-CBC decryption process along with the key derived from the `userId` and the extracted salt.

**How User ID Spoofing is Prevented:**

The current implementation now includes basic token-based authentication to mitigate user ID spoofing. Upon successful registration and login, a unique, time-limited token is issued to the user. Subsequent requests to access protected resources (like storing and retrieving messages) require this token to be included in the `Authorization` header of the HTTP request. The server verifies the token to ensure the user is authenticated and authorized to perform the requested action for the associated `userId`. While basic, this adds a layer of security compared to relying solely on the `userId` in the request body.

**Message Expiry:**

Messages are now automatically deleted after 10 minutes. When a message is stored, a timestamp is recorded. Before processing requests for messages, the system checks for and removes any messages older than the defined expiry time.

## Debug Task

The `debug_code.py` file contains the `broken_decrypt()` function and its fix.

**Issue Identification:**

The `broken_decrypt()` function had the following critical flaws:

1.  **Incorrect Payload Slicing:** It attempted to extract the Initialization Vector (IV) by taking the first 16 bytes of the base64 decoded payload. However, the `encrypt_message()` function in `app.py` prepends the 16-byte salt *before* the IV. Therefore, `broken_decrypt()` was incorrectly treating the salt as the IV and the actual IV as part of the ciphertext.
2.  **Incorrect Key Derivation:** The `broken_decrypt()` function called `generate_salt()` during the decryption process. This would generate a *new*, random salt, which would be different from the salt used during encryption. Consequently, the `derive_key()` function would produce an incorrect decryption key, leading to the decryption failure. The correct approach is to use the salt that was used during encryption, which is embedded in the encrypted payload.

**Test Case:**

The `test_broken_decrypt()` function in `debug_code.py` sets up a scenario by:

1.  Generating a salt and deriving an encryption key for a specific `user_id`.
2.  Creating a plaintext message and padding it.
3.  Encrypting the padded plaintext using AES-256-CBC with a randomly generated IV.
4.  Constructing the encrypted payload by prepending the salt and the IV to the ciphertext.
5.  Base64 encoding the payload.
6.  Calling the `broken_decrypt()` function with this base64 encoded message and the correct `user_id`.
7.  The assertion `assert "Decryption failed" in decrypted_message or plaintext != decrypted_message` verifies that the `broken_decrypt()` function either explicitly indicates a decryption failure or produces a plaintext that is different from the original, demonstrating the broken logic.

**Fix Explanation (Implemented in `fixed_decrypt()`):**

```python
def fixed_decrypt(encrypted_message_b64, user_id):
    try:
        encrypted_payload = base64.b64decode(encrypted_message_b64)
        # FIXED: Extract the salt (first 16 bytes)
        salt = encrypted_payload[:16]
        # FIXED: Extract the IV (next 16 bytes)
        iv = encrypted_payload[16:32]
        # Extract the ciphertext (remaining bytes)
        ciphertext = encrypted_payload[32:]
        # FIXED: Derive the key using the extracted salt
        key = derive_key(user_id, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption failed: {e}"

## Instructions to Run the Project

1.  Open your terminal or command prompt.
2.  Navigate to the directory where you want to save the project.
3.  Run the following command :

    ```bash
    git clone https://github.com/samukele-dev/Secure_Messaging_API.git
    ```

4.  Once the repository is cloned, navigate into the project directory:

    ```bash
    cd secure_messaging_api
    ```

5.  Ensure you have Python 3.6+ installed.
6.  It is highly recommended to create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate   # On Windows
    ```
7.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
8.  Run the Flask development server:
    ```bash
    python app.py
    ```
    The server will typically start at `http://127.0.0.1:5000`.
9.  **Register and Log In:**
    * **Register:** Use `curl` to register a user (replace `your_desired_user_id` for example 'test_user'):
      ```bash
      curl -X POST -H "Content-Type: application/json" -d '{"userId": "your_desired_user_id"}' http://127.0.0.1:5000/register
      ```
    * **Log In:** Use `curl` to log in and get a token (replace `your_desired_user_id`):
      ```bash
      curl -X POST -H "Content-Type: application/json" -d '{"userId": "your_desired_user_id"}' http://127.0.0.1:5000/login
      ```
      This will return a JSON response containing a `token`. Copy this token.
10. **Interacting with API Endpoints using `curl`:**
    * **POST /messages (Store a message):** Include the token in the `Authorization` header:
      ```bash
      curl -X POST -H "Content-Type: application/json" -H "Authorization: <your_copied_token>" -d '{"message": "This is my secret message."}' http://127.0.0.1:5000/messages
      ```
      Replace `<your_copied_token>` with the actual token.
    * **GET /messages/<user_id> (Retrieve messages):** Include the token in the `Authorization` header and use the correct `userId`:
      ```bash
      curl -X GET -H "Authorization: <your_copied_token>" http://127.0.0.1:5000/messages/your_desired_user_id
      ```
      Replace `<your_copied_token>` and `your_desired_user_id` with your actual values.
    * **POST /debug/decrypt (Debug decryption):**
      ```bash
      curl -X POST -H "Content-Type: application/json" -d '{"userId": "test_user", "encrypted_message": "base64_encoded_message"}' http://127.0.0.1:5000/debug/decrypt
      ```
      Replace `"base64_encoded_message"` with an actual base64 encoded encrypted message you want to debug.

Remember to stop the Flask development server by pressing `Ctrl + C` in your terminal when you are finished testing.