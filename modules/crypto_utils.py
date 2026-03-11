"""
SteganoSafe — Cryptography Module
==================================
Implements:
- AES-256-GCM encryption/decryption
- PBKDF2 password-based key derivation
- SHA-256 file integrity hashing
- Secure payload packaging/unpackaging

Security highlights:
- AES-256-GCM provides both confidentiality and integrity
- PBKDF2 with 100,000 iterations resists brute-force attacks
- Random salt and nonce per encryption operation
- SHA-256 hash for tamper detection
"""

import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore


class CryptoUtils:
    """
    Cryptographic operations for SteganoSafe.
    
    Encryption Flow:
        password → PBKDF2 → AES-256 key → AES-GCM encrypt → ciphertext + tag
    
    Payload Format:
        [4B name_len][name_bytes][16B salt][12B nonce][16B tag][encrypted_data]
    """

    # PBKDF2 iterations — high for security
    PBKDF2_ITERATIONS = 100_000
    # Salt size in bytes
    SALT_SIZE = 16
    # AES-GCM nonce size
    NONCE_SIZE = 12
    # AES key size (256 bits)
    KEY_SIZE = 32
    # GCM authentication tag size
    TAG_SIZE = 16

    def derive_key(self, password, salt):
        """
        Derive a 256-bit AES key from password using PBKDF2.
        
        Args:
            password: User's password string
            salt: Random 16-byte salt
            
        Returns:
            32-byte derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt(self, plaintext, password):
        """
        Encrypt data using AES-256-GCM with PBKDF2 key derivation.
        
        Args:
            plaintext: Raw bytes to encrypt
            password: Encryption password
            
        Returns:
            tuple: (ciphertext, salt, nonce, tag)
            
        Security:
            - Random salt ensures unique key per encryption
            - Random nonce ensures unique ciphertext per encryption
            - GCM mode provides authenticated encryption
        """
        # Generate random salt and nonce
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)

        # Derive key from password
        key = self.derive_key(password, salt)

        # Encrypt using AES-256-GCM
        aesgcm = AESGCM(key)
        # AES-GCM appends the tag to the ciphertext
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        # Split ciphertext and tag
        ciphertext = ciphertext_with_tag[:-self.TAG_SIZE]
        tag = ciphertext_with_tag[-self.TAG_SIZE:]

        return ciphertext, salt, nonce, tag

    def decrypt(self, ciphertext, password, salt, nonce, tag):
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data bytes
            password: Decryption password
            salt: Salt used during encryption
            nonce: Nonce used during encryption
            tag: GCM authentication tag
            
        Returns:
            Decrypted plaintext bytes, or None if authentication fails
            
        Security:
            - GCM tag verification ensures data integrity
            - Wrong password → authentication failure (not garbage output)
        """
        try:
            # Derive key from password
            key = self.derive_key(password, salt)

            # Reconstruct ciphertext + tag
            ciphertext_with_tag = ciphertext + tag

            # Decrypt using AES-256-GCM
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

            return plaintext
        except Exception:
            # Authentication failure — wrong password or tampered data
            return None

    def compute_hash(self, data):
        """
        Compute SHA-256 hash for integrity verification.
        
        Args:
            data: Bytes to hash
            
        Returns:
            Hex string of SHA-256 hash
        """
        return hashlib.sha256(data).hexdigest()

    def package_payload(self, encrypted_data, salt, nonce, tag, original_name):
        """
        Package all encryption artifacts into a single payload for steganographic embedding.
        
        Format:
            [4B name_length][name_bytes][16B salt][12B nonce][16B tag][encrypted_data]
        
        Args:
            encrypted_data: AES-GCM ciphertext
            salt: PBKDF2 salt
            nonce: AES-GCM nonce
            tag: GCM authentication tag
            original_name: Original filename
            
        Returns:
            Packed payload bytes
        """
        name_bytes = original_name.encode('utf-8')
        name_len = len(name_bytes)

        payload = struct.pack('>I', name_len)  # 4 bytes: name length
        payload += name_bytes                   # Variable: filename
        payload += salt                         # 16 bytes: PBKDF2 salt
        payload += nonce                        # 12 bytes: AES-GCM nonce
        payload += tag                          # 16 bytes: GCM tag
        payload += encrypted_data               # Variable: ciphertext

        return payload

    def unpackage_payload(self, payload):
        """
        Unpackage a steganographic payload back into encryption components.
        
        Args:
            payload: Packed payload bytes
            
        Returns:
            tuple: (encrypted_data, salt, nonce, tag, original_name)
            
        Raises:
            ValueError: If payload format is invalid
        """
        try:
            offset = 0

            # Read name length (4 bytes)
            name_len = struct.unpack('>I', payload[offset:offset + 4])[0]
            offset += 4

            # Read filename
            original_name = payload[offset:offset + name_len].decode('utf-8')
            offset += name_len

            # Read salt (16 bytes)
            salt = payload[offset:offset + self.SALT_SIZE]
            offset += self.SALT_SIZE

            # Read nonce (12 bytes)
            nonce = payload[offset:offset + self.NONCE_SIZE]
            offset += self.NONCE_SIZE

            # Read tag (16 bytes)
            tag = payload[offset:offset + self.TAG_SIZE]
            offset += self.TAG_SIZE

            # Read encrypted data (remaining)
            encrypted_data = payload[offset:]

            return encrypted_data, salt, nonce, tag, original_name

        except Exception as e:
            raise ValueError(f"Invalid payload format: {e}")
