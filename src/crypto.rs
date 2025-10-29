//! Cryptography module for encrypted communication between parent and child EVMs
//!
//! This module provides:
//! - Abstract traits for pluggable encryption schemes
//! - Key generation and management for the enclave (child EVM)
//! - Default implementation using ChaCha20-Poly1305 (AEAD cipher) with X25519 key exchange
//! - Utilities for handling encrypted payloads
//!
//! ## Architecture
//!
//! The crypto abstraction consists of several traits:
//! - `CryptoScheme`: Main trait defining the encryption scheme
//! - `EnclaveKeyPair`: Trait for enclave (child EVM) key management
//! - `UserKeyPair`: Trait for user key management
//! - `EncryptedPayload`: Trait for working with encrypted data
//!
//! This allows plugging in different encryption schemes (e.g., RSA, post-quantum crypto)
//! without changing the rest of the codebase.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// Main trait defining a cryptographic scheme for secure enclave communication
///
/// This trait allows different encryption schemes to be plugged into the system.
/// Implementors must provide key generation and encryption/decryption capabilities.
pub trait CryptoScheme: Clone + std::fmt::Debug + Send + Sync {
    /// Type representing enclave (child EVM) keys
    type EnclaveKeys: EnclaveKeyPair;
    /// Type representing user keys
    type UserKeys: UserKeyPair;

    /// Create a new instance of this crypto scheme
    fn new() -> Self;
}

/// Trait for enclave (child EVM) key pairs
///
/// The enclave holds private keys that never leave the secure environment.
/// Users encrypt data using the enclave's public key.
pub trait EnclaveKeyPair: Clone + std::fmt::Debug + Send + Sync {
    /// Generate a new key pair for the enclave
    fn generate() -> Self;

    /// Get the public key as bytes (safe to share publicly)
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Decrypt data that was encrypted for this enclave
    ///
    /// The exact format depends on the implementation, but generally:
    /// - Should include authentication/integrity checks
    /// - Should include sender's public key for response encryption
    /// - Returns the plaintext data
    fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt response data for a specific user
    ///
    /// # Arguments
    /// * `data` - The plaintext to encrypt
    /// * `recipient_public_key` - The user's public key (as bytes)
    ///
    /// Returns encrypted payload that only the user can decrypt
    fn encrypt_response(&self, data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for user key pairs
///
/// Users generate keys to encrypt data for the enclave and decrypt responses.
pub trait UserKeyPair: Clone + std::fmt::Debug + Send + Sync {
    /// Generate a new key pair for a user
    fn generate() -> Self;

    /// Get the public key as bytes (sent with transactions)
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Encrypt data for the enclave
    ///
    /// # Arguments
    /// * `data` - The plaintext to encrypt
    /// * `enclave_public_key` - The enclave's public key (as bytes)
    ///
    /// Returns encrypted payload that only the enclave can decrypt
    fn encrypt_for_enclave(&self, data: &[u8], enclave_public_key: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt response from the enclave
    ///
    /// Returns the plaintext data
    fn decrypt_response(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>>;
}

//
// ============================================================================
// Default Implementation: ChaCha20-Poly1305 + X25519
// ============================================================================
//

/// Default crypto scheme using ChaCha20-Poly1305 for encryption and X25519 for key exchange
#[derive(Clone, Debug)]
pub struct ChaCha20X25519Scheme;

impl CryptoScheme for ChaCha20X25519Scheme {
    type EnclaveKeys = EnclaveKeys;
    type UserKeys = UserKeys;

    fn new() -> Self {
        Self
    }
}

/// Size of nonce for ChaCha20-Poly1305 (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Size of X25519 public key (256 bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Enclave key pair for the child EVM
/// In production, this would be securely stored in the enclave
#[derive(Clone)]
pub struct EnclaveKeys {
    /// Private key (secret) - never leaves the enclave
    secret: StaticSecret,
    /// Public key - can be shared publicly
    pub public_key: PublicKey,
}

impl std::fmt::Debug for EnclaveKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveKeys")
            .field("public_key", &hex::encode(self.public_key.as_bytes()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl EnclaveKeys {
    /// Derive a shared secret with a user's public key
    fn derive_shared_secret(&self, user_public_key: &PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(user_public_key).as_bytes()
    }

    /// Get the public key as bytes (array version for backward compatibility)
    pub fn public_key_bytes_array(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Encrypt response data for a specific user (X25519 PublicKey version for backward compatibility)
    pub fn encrypt_response_x25519(
        &self,
        data: &[u8],
        user_public_key: &PublicKey,
    ) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Derive shared secret
        let shared_secret = self.derive_shared_secret(user_public_key);

        // Encrypt
        let cipher = ChaCha20Poly1305::new(shared_secret.as_ref().into());
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Construct payload: [nonce][enclave_public_key][ciphertext]
        let mut payload = Vec::with_capacity(NONCE_SIZE + PUBLIC_KEY_SIZE + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(self.public_key.as_bytes());
        payload.extend_from_slice(&ciphertext);

        Ok(payload)
    }
}

impl EnclaveKeyPair for EnclaveKeys {
    fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>> {
        if encrypted_payload.len() < NONCE_SIZE + PUBLIC_KEY_SIZE {
            return Err(anyhow!("Encrypted payload too short"));
        }

        // Extract nonce
        let nonce_bytes: [u8; NONCE_SIZE] = encrypted_payload[0..NONCE_SIZE]
            .try_into()
            .map_err(|_| anyhow!("Invalid nonce"))?;
        let nonce = Nonce::from(nonce_bytes);

        // Extract user's public key
        let user_public_key_bytes: [u8; PUBLIC_KEY_SIZE] = encrypted_payload
            [NONCE_SIZE..NONCE_SIZE + PUBLIC_KEY_SIZE]
            .try_into()
            .map_err(|_| anyhow!("Invalid public key"))?;
        let user_public_key = PublicKey::from(user_public_key_bytes);

        // Derive shared secret
        let shared_secret = self.derive_shared_secret(&user_public_key);

        // Decrypt
        let cipher = ChaCha20Poly1305::new(shared_secret.as_ref().into());
        let ciphertext = &encrypted_payload[NONCE_SIZE + PUBLIC_KEY_SIZE..];

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))
    }

    fn encrypt_response(&self, data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        if recipient_public_key.len() != PUBLIC_KEY_SIZE {
            return Err(anyhow!("Invalid public key size"));
        }

        // Convert bytes to PublicKey
        let user_public_key_bytes: [u8; PUBLIC_KEY_SIZE] = recipient_public_key
            .try_into()
            .map_err(|_| anyhow!("Invalid public key"))?;
        let user_public_key = PublicKey::from(user_public_key_bytes);

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Derive shared secret
        let shared_secret = self.derive_shared_secret(&user_public_key);

        // Encrypt
        let cipher = ChaCha20Poly1305::new(shared_secret.as_ref().into());
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Construct payload: [nonce][enclave_public_key][ciphertext]
        let mut payload = Vec::with_capacity(NONCE_SIZE + PUBLIC_KEY_SIZE + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(self.public_key.as_bytes());
        payload.extend_from_slice(&ciphertext);

        Ok(payload)
    }
}

/// User key pair for interacting with the enclave
/// Users generate ephemeral keys for each session or maintain persistent keys
#[derive(Clone)]
pub struct UserKeys {
    /// Private key (secret) - stays with the user
    secret: StaticSecret,
    /// Public key - sent with transactions
    pub public_key: PublicKey,
}

impl std::fmt::Debug for UserKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserKeys")
            .field("public_key", &hex::encode(self.public_key.as_bytes()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl UserKeys {
    /// Create from a specific secret (for testing)
    pub fn from_secret(secret: StaticSecret) -> Self {
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    /// Get the public key as bytes (array version for backward compatibility)
    pub fn public_key_bytes_array(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Derive a shared secret with the enclave's public key
    fn derive_shared_secret(&self, enclave_public_key: &PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(enclave_public_key).as_bytes()
    }

    /// Encrypt data for the enclave (X25519 PublicKey version for backward compatibility)
    pub fn encrypt_for_enclave_x25519(
        &self,
        data: &[u8],
        enclave_public_key: &PublicKey,
    ) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Derive shared secret
        let shared_secret = self.derive_shared_secret(enclave_public_key);

        // Encrypt
        let cipher = ChaCha20Poly1305::new(shared_secret.as_ref().into());
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Construct payload: [nonce][user_public_key][ciphertext]
        let mut payload = Vec::with_capacity(NONCE_SIZE + PUBLIC_KEY_SIZE + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(self.public_key.as_bytes());
        payload.extend_from_slice(&ciphertext);

        Ok(payload)
    }
}

impl UserKeyPair for UserKeys {
    fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn encrypt_for_enclave(&self, data: &[u8], enclave_public_key: &[u8]) -> Result<Vec<u8>> {
        if enclave_public_key.len() != PUBLIC_KEY_SIZE {
            return Err(anyhow!("Invalid public key size"));
        }

        // Convert bytes to PublicKey
        let enclave_public_key_bytes: [u8; PUBLIC_KEY_SIZE] = enclave_public_key
            .try_into()
            .map_err(|_| anyhow!("Invalid public key"))?;
        let enclave_pk = PublicKey::from(enclave_public_key_bytes);

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Derive shared secret
        let shared_secret = self.derive_shared_secret(&enclave_pk);

        // Encrypt
        let cipher = ChaCha20Poly1305::new(shared_secret.as_ref().into());
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Construct payload: [nonce][user_public_key][ciphertext]
        let mut payload = Vec::with_capacity(NONCE_SIZE + PUBLIC_KEY_SIZE + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(self.public_key.as_bytes());
        payload.extend_from_slice(&ciphertext);

        Ok(payload)
    }

    fn decrypt_response(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>> {
        if encrypted_payload.len() < NONCE_SIZE + PUBLIC_KEY_SIZE {
            return Err(anyhow!("Encrypted payload too short"));
        }

        // Extract nonce
        let nonce_bytes: [u8; NONCE_SIZE] = encrypted_payload[0..NONCE_SIZE]
            .try_into()
            .map_err(|_| anyhow!("Invalid nonce"))?;
        let nonce = Nonce::from(nonce_bytes);

        // Extract enclave's public key
        let enclave_public_key_bytes: [u8; PUBLIC_KEY_SIZE] = encrypted_payload
            [NONCE_SIZE..NONCE_SIZE + PUBLIC_KEY_SIZE]
            .try_into()
            .map_err(|_| anyhow!("Invalid public key"))?;
        let enclave_public_key = PublicKey::from(enclave_public_key_bytes);

        // Derive shared secret
        let shared_secret = self.derive_shared_secret(&enclave_public_key);

        // Decrypt
        let cipher = ChaCha20Poly1305::new(shared_secret.as_ref().into());
        let ciphertext = &encrypted_payload[NONCE_SIZE + PUBLIC_KEY_SIZE..];

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))
    }
}

//
// ============================================================================
// Example: Creating a Custom Encryption Scheme
// ============================================================================
//
// This example shows how to implement a custom encryption scheme.
// You could use RSA, post-quantum crypto, or any other scheme.
//
// ```rust,ignore
// use anyhow::Result;
//
// // Step 1: Define your key structures
// #[derive(Clone, Debug)]
// pub struct RsaEnclaveKeys {
//     private_key: RsaPrivateKey,
//     public_key: RsaPublicKey,
// }
//
// #[derive(Clone, Debug)]
// pub struct RsaUserKeys {
//     private_key: RsaPrivateKey,
//     public_key: RsaPublicKey,
// }
//
// // Step 2: Implement the EnclaveKeyPair trait
// impl EnclaveKeyPair for RsaEnclaveKeys {
//     fn generate() -> Self {
//         // Generate RSA key pair
//         let mut rng = rand::thread_rng();
//         let bits = 2048;
//         let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
//         let public_key = RsaPublicKey::from(&private_key);
//         Self { private_key, public_key }
//     }
//
//     fn public_key_bytes(&self) -> Vec<u8> {
//         // Serialize public key
//         self.public_key.to_pkcs1_der().unwrap().as_bytes().to_vec()
//     }
//
//     fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>> {
//         // Implement RSA decryption
//         // Format: [sender_pubkey_len (4 bytes)][sender_pubkey][encrypted_data]
//         // ...
//     }
//
//     fn encrypt_response(&self, data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
//         // Implement RSA encryption
//         // ...
//     }
// }
//
// // Step 3: Implement the UserKeyPair trait
// impl UserKeyPair for RsaUserKeys {
//     fn generate() -> Self {
//         // Similar to EnclaveKeyPair::generate
//         // ...
//     }
//
//     fn public_key_bytes(&self) -> Vec<u8> {
//         // Similar to EnclaveKeyPair::public_key_bytes
//         // ...
//     }
//
//     fn encrypt_for_enclave(&self, data: &[u8], enclave_public_key: &[u8]) -> Result<Vec<u8>> {
//         // Implement RSA encryption
//         // ...
//     }
//
//     fn decrypt_response(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>> {
//         // Implement RSA decryption
//         // ...
//     }
// }
//
// // Step 4: Define your crypto scheme
// #[derive(Clone, Debug)]
// pub struct RsaCryptoScheme;
//
// impl CryptoScheme for RsaCryptoScheme {
//     type EnclaveKeys = RsaEnclaveKeys;
//     type UserKeys = RsaUserKeys;
//
//     fn new() -> Self {
//         Self
//     }
// }
//
// // Step 5: Use your custom scheme with ChildEvm
// let child_evm: ChildEvm<EvmContext, (), RsaEnclaveKeys> = ChildEvm::new(
//     ctx,
//     (),
//     cross_evm_handler,
// );
// ```
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();

        // Keys should be 32 bytes
        assert_eq!(enclave_keys.public_key_bytes().len(), 32);
        assert_eq!(user_keys.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();

        let plaintext = b"Hello from user to enclave!";

        // User encrypts for enclave
        let encrypted = user_keys
            .encrypt_for_enclave(plaintext, &enclave_keys.public_key_bytes())
            .expect("Encryption failed");

        // Enclave decrypts
        let decrypted = enclave_keys.decrypt(&encrypted).expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_response_encryption() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();

        let response_data = b"Hello from enclave to user!";

        // Enclave encrypts response
        let encrypted_response = enclave_keys
            .encrypt_response(response_data, &user_keys.public_key_bytes())
            .expect("Encryption failed");

        // User decrypts response
        let decrypted = user_keys
            .decrypt_response(&encrypted_response)
            .expect("Decryption failed");

        assert_eq!(decrypted, response_data);
    }

    #[test]
    fn test_bidirectional_encryption() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();

        // User -> Enclave
        let request = b"increment()";
        let encrypted_request = user_keys
            .encrypt_for_enclave(request, &enclave_keys.public_key_bytes())
            .expect("Request encryption failed");
        let decrypted_request = enclave_keys
            .decrypt(&encrypted_request)
            .expect("Request decryption failed");
        assert_eq!(decrypted_request, request);

        // Enclave -> User
        let response = b"success: counter=1";
        let encrypted_response = enclave_keys
            .encrypt_response(response, &user_keys.public_key_bytes())
            .expect("Response encryption failed");
        let decrypted_response = user_keys
            .decrypt_response(&encrypted_response)
            .expect("Response decryption failed");
        assert_eq!(decrypted_response, response);
    }

    #[test]
    fn test_wrong_key_cannot_decrypt() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();
        let wrong_keys = UserKeys::generate();

        let plaintext = b"Secret message";

        // User encrypts for enclave
        let encrypted = user_keys
            .encrypt_for_enclave(plaintext, &enclave_keys.public_key_bytes())
            .expect("Encryption failed");

        // Different user tries to decrypt (should fail)
        let result = wrong_keys.decrypt_response(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_data_fails_decryption() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();

        let plaintext = b"Original message";

        // User encrypts for enclave
        let mut encrypted = user_keys
            .encrypt_for_enclave(plaintext, &enclave_keys.public_key_bytes())
            .expect("Encryption failed");

        // Tamper with the ciphertext (flip a bit)
        if let Some(byte) = encrypted.get_mut(NONCE_SIZE + PUBLIC_KEY_SIZE + 10) {
            *byte ^= 0x01;
        }

        // Decryption should fail due to authentication tag mismatch
        let result = enclave_keys.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_payload_format() {
        let enclave_keys = EnclaveKeys::generate();
        let user_keys = UserKeys::generate();

        let plaintext = b"Test";

        let encrypted = user_keys
            .encrypt_for_enclave(plaintext, &enclave_keys.public_key_bytes())
            .expect("Encryption failed");

        // Check payload structure
        assert!(encrypted.len() >= NONCE_SIZE + PUBLIC_KEY_SIZE + plaintext.len());

        // Nonce should be first 12 bytes
        assert_eq!(&encrypted[0..NONCE_SIZE].len(), &12);

        // Public key should be next 32 bytes
        assert_eq!(
            &encrypted[NONCE_SIZE..NONCE_SIZE + PUBLIC_KEY_SIZE],
            &user_keys.public_key_bytes()[..]
        );
    }
}
