use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use ring::{rand::SecureRandom, aead, agreement, hkdf, rand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::Rng;

// ============================================================================
// CRYPTO MANAGER
// ============================================================================

pub struct CryptoManager {
    key_store: HashMap<String, Vec<u8>>, // user_id -> encryption_key
    salt: [u8; 32],
    rng: rand::SystemRandom,
}

impl CryptoManager {
    pub fn new() -> Self {
        let rng = rand::SystemRandom::new();
        let mut salt = [0u8; 32];
        let mut bytes = salt;
        rng.fill(&mut bytes)
            .expect("Failed to generate random salt");
        let salt = bytes;
        Self {
            key_store: HashMap::new(),
            salt,
            rng,
        }
    }

    // ============================================================================
    // KEY MANAGEMENT
    // ============================================================================

    /// Generate a new encryption key for a user
    pub fn generate_user_key(&mut self, user_id: &str) -> Result<String> {
        let mut key_bytes = [0u8; 32];
        let mut bytes = key_bytes;
        self.rng.fill(&mut bytes)
            .context("Failed to generate random key")?;
        let key_bytes = bytes;
        let key_base64 = general_purpose::STANDARD.encode(&key_bytes);
        self.key_store.insert(user_id.to_string(), key_bytes.to_vec());
        Ok(key_base64)
    }

    /// Import an existing key for a user
    pub fn import_user_key(&mut self, user_id: &str, key_base64: &str) -> Result<()> {
        let key_bytes = general_purpose::STANDARD.decode(key_base64)
            .context("Failed to decode base64 key")?;

        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key length, expected 32 bytes"));
        }

        self.key_store.insert(user_id.to_string(), key_bytes);
        Ok(())
    }

    /// Get a user's encryption key
    fn get_user_key(&self, user_id: &str) -> Result<&[u8]> {
        self.key_store.get(user_id)
            .map(|key| key.as_slice())
            .context("No encryption key found for user")
    }

    /// Derive a chat-specific key from user keys
    fn derive_chat_key(&self, user_ids: &[String]) -> Result<Vec<u8>> {
        if user_ids.is_empty() {
            return Err(anyhow::anyhow!("No users provided for key derivation"));
        }

        // Sort user IDs to ensure consistent key derivation
        let mut sorted_ids = user_ids.to_vec();
        sorted_ids.sort();

        // Combine all user keys and derive a chat key
        let mut combined_keys = Vec::new();
        for user_id in &sorted_ids {
            let key = self.get_user_key(user_id)?;
            combined_keys.extend_from_slice(key);
        }

        // Use HKDF to derive a secure chat key
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &self.salt);
        let prk = salt.extract(&combined_keys);
        let okm = prk.expand(&[b"chat_key"], hkdf::HKDF_SHA256)
            .context("HKDF expansion failed")?;

        let mut chat_key = vec![0u8; 32];
        okm.fill(&mut chat_key)
            .context("Failed to derive chat key")?;

        Ok(chat_key)
    }

    // ============================================================================
    // SYMMETRIC ENCRYPTION (AES-GCM)
    // ============================================================================

    /// Encrypt plaintext using AES-256-GCM
    pub fn encrypt_message(&self, plaintext: &str, user_ids: &[String]) -> Result<EncryptedMessage> {
        let chat_key = self.derive_chat_key(user_ids)?;
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &chat_key)
                .context("Invalid encryption key")?
        );

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        let mut bytes = nonce_bytes;
        self.rng.fill(&mut bytes)
            .context("Failed to generate nonce")?;
        let nonce_bytes = bytes;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        // Prepare plaintext and additional data
        let mut in_out = plaintext.as_bytes().to_vec();
        let additional_data = b"message";

        // Encrypt in-place
        sealing_key.seal_in_place_append_tag(nonce, aead::Aad::from(additional_data), &mut in_out)
            .context("Encryption failed")?;

        Ok(EncryptedMessage {
            ciphertext: general_purpose::STANDARD.encode(&in_out),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            key_id: user_ids.join(","), // For key derivation
            version: "aes-256-gcm".to_string(),
        })
    }

    /// Decrypt ciphertext using AES-256-GCM
    pub fn decrypt_message(&self, encrypted: &EncryptedMessage, user_id: &str) -> Result<String> {
        // Parse user IDs from key_id
        let user_ids: Vec<String> = encrypted.key_id.split(',').map(|s| s.to_string()).collect();

        let chat_key = self.derive_chat_key(&user_ids)?;
        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &chat_key)
                .context("Invalid decryption key")?
        );

        // Decode nonce and ciphertext
        let nonce_bytes = general_purpose::STANDARD.decode(&encrypted.nonce)
            .context("Invalid nonce encoding")?;
        let mut ciphertext = general_purpose::STANDARD.decode(&encrypted.ciphertext)
            .context("Invalid ciphertext encoding")?;

        if nonce_bytes.len() != 12 {
            return Err(anyhow::anyhow!("Invalid nonce length"));
        }

        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
            .context("Invalid nonce")?;

        let additional_data = b"message";

        // Decrypt in-place
        let plaintext = opening_key.open_in_place(nonce, aead::Aad::from(additional_data), &mut ciphertext)
            .context("Decryption failed")?;

        String::from_utf8(plaintext.to_vec())
            .context("Decrypted data is not valid UTF-8")
    }

    // ============================================================================
    // FILE ENCRYPTION
    // ============================================================================

    /// Encrypt a file with chunk-based encryption for large files
    pub fn encrypt_file(&self, data: &[u8], user_ids: &[String]) -> Result<EncryptedFile> {
        let chat_key = self.derive_chat_key(user_ids)?;
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &chat_key)
                .context("Invalid encryption key")?
        );

        // Generate file nonce
        let mut file_nonce_bytes = [0u8; 12];
        let mut bytes = file_nonce_bytes;
        self.rng.fill(&mut bytes)
            .context("Failed to generate file nonce")?;
        let file_nonce_bytes = bytes;

        let mut encrypted_data = data.to_vec();
        let additional_data = b"file";

        // Encrypt file data
        sealing_key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(file_nonce_bytes),
            aead::Aad::from(additional_data),
            &mut encrypted_data
        ).context("File encryption failed")?;

        // Generate HMAC for integrity verification
        let hmac_key = hkdf::Salt::new(hkdf::HKDF_SHA256, &self.salt)
            .extract(&chat_key);
        let hmac_okm = hmac_key.expand(&[b"file_hmac"], hkdf::HKDF_SHA256)
            .context("HMAC key derivation failed")?;

        let mut hmac_key_bytes = vec![0u8; 32];
        hmac_okm.fill(&mut hmac_key_bytes)
            .context("Failed to derive HMAC key")?;

        let hmac = Self::compute_hmac(&encrypted_data, &hmac_key_bytes);

        Ok(EncryptedFile {
            data: encrypted_data,
            nonce: file_nonce_bytes.to_vec(),
            hmac: general_purpose::STANDARD.encode(hmac),
            key_id: user_ids.join(","),
            original_size: data.len() as u64,
        })
    }

    /// Decrypt a file
    pub fn decrypt_file(&self, encrypted_file: &EncryptedFile, user_id: &str) -> Result<Vec<u8>> {
        let user_ids: Vec<String> = encrypted_file.key_id.split(',').map(|s| s.to_string()).collect();
        let chat_key = self.derive_chat_key(&user_ids)?;

        // Verify HMAC first
        let hmac_key = hkdf::Salt::new(hkdf::HKDF_SHA256, &self.salt)
            .extract(&chat_key);
        let hmac_okm = hmac_key.expand(&[b"file_hmac"], hkdf::HKDF_SHA256)
            .context("HMAC key derivation failed")?;

        let mut hmac_key_bytes = vec![0u8; 32];
        hmac_okm.fill(&mut hmac_key_bytes)
            .context("Failed to derive HMAC key")?;

        let computed_hmac = Self::compute_hmac(&encrypted_file.data, &hmac_key_bytes);
        let stored_hmac = general_purpose::STANDARD.decode(&encrypted_file.hmac)
            .context("Invalid HMAC encoding")?;

        if computed_hmac != stored_hmac {
            return Err(anyhow::anyhow!("File integrity check failed - HMAC mismatch"));
        }

        // Decrypt file data
        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &chat_key)
                .context("Invalid decryption key")?
        );

        if encrypted_file.nonce.len() != 12 {
            return Err(anyhow::anyhow!("Invalid nonce length"));
        }

        let mut ciphertext = encrypted_file.data.clone();
        let nonce_bytes: [u8; 12] = encrypted_file.nonce.as_slice().try_into()
            .context("Invalid nonce")?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let additional_data = b"file";

        let plaintext = opening_key.open_in_place(nonce, aead::Aad::from(additional_data), &mut ciphertext)
            .context("File decryption failed")?;

        Ok(plaintext.to_vec())
    }

    // ============================================================================
    // PASSWORD HASHING (Argon2)
    // ============================================================================

    use argon2::{self, Config, ThreadMode, Variant, Version};
pub fn hash_password(password: &str) -> Result<String> {
    use rand::Rng;
    
    let salt: [u8; 16] = rand::thread_rng().gen();
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 4096,
        time_cost: 3,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config)?;
    Ok(hash)
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
    Ok(argon2::verify_encoded(hash, password.as_bytes())?)
}
    // ============================================================================
    // DIGITAL SIGNATURES
    // ============================================================================

    /// Generate an Ed25519 key pair for digital signatures
    pub fn generate_keypair(&self) -> Result<KeyPair> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .context("Failed to generate key pair")?;

        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .context("Failed to parse generated key pair")?;

        Ok(KeyPair {
            public_key: general_purpose::STANDARD.encode(key_pair.public_key().as_ref()),
            private_key: general_purpose::STANDARD.encode(pkcs8_bytes.as_ref()),
        })
    }

    /// Sign data with a private key
    pub fn sign_data(&self, data: &[u8], private_key_pkcs8: &str) -> Result<String> {
        let key_bytes = general_purpose::STANDARD.decode(private_key_pkcs8)
            .context("Invalid private key encoding")?;

        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&key_bytes)
            .context("Invalid private key format")?;

        let signature = key_pair.sign(data);
        Ok(general_purpose::STANDARD.encode(signature.as_ref()))
    }

    /// Verify a signature with a public key
    pub fn verify_signature(&self, data: &[u8], signature: &str, public_key: &str) -> Result<bool> {
        let signature_bytes = general_purpose::STANDARD.decode(signature)
            .context("Invalid signature encoding")?;

        let public_key_bytes = general_purpose::STANDARD.decode(public_key)
            .context("Invalid public key encoding")?;

        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &public_key_bytes,
        );

        match public_key.verify(data, &signature_bytes) {
            Ok(()) => Ok(true),
            Err(ring::error::Unspecified) => Ok(false),
            Err(e) => Err(anyhow::anyhow!("Signature verification error: {:?}", e)),
        }
    }

    // ============================================================================
    // SECURE RANDOM GENERATION
    // ============================================================================

    /// Generate a cryptographically secure random string
    pub fn generate_random_string(&self, length: usize) -> Result<String> {
        let mut bytes = vec![0u8; length];
        let mut bytes2 = bytes.clone();
        self.rng.fill(&mut bytes2)
            .context("Failed to generate random bytes for string")?;
        let bytes = bytes2;

        Ok(general_purpose::STANDARD.encode(&bytes))
    }

    /// Generate a secure random UUID
    pub fn generate_secure_uuid(&self) -> Result<String> {
        let mut bytes = [0u8; 16];
        let mut bytes2 = bytes;
        self.rng.fill(&mut bytes2)
            .context("Failed to generate random bytes")?;
        let bytes = bytes2;
        Ok(Uuid::from_slice(&bytes)?.to_string())
    }

    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================

    /// Compute HMAC-SHA256 for data integrity
    fn compute_hmac(data: &[u8], key: &[u8]) -> Vec<u8> {
        use ring::hmac;

        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&key, data);
        tag.as_ref().to_vec()
    }

    /// Securely compare two values in constant time
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && {
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

    /// Securely wipe sensitive data from memory
    pub fn secure_wipe(&mut self, data: &mut [u8]) {
        use ring::rand::SecureRandom;

        if !data.is_empty() {
            let mut bytes = vec![0u8; data.len()];
            let _ = self.rng.fill(&mut bytes);
        }

        // Additional zeroization for good measure
        for byte in data.iter_mut() {
            *byte = 0;
        }
    }
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: String,
    pub nonce: String,
    pub key_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFile {
    pub data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub hmac: String,
    pub key_id: String,
    pub original_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchange {
    pub ephemeral_public: String,
    pub signature: String,
    pub user_id: String,
}

// ============================================================================
// KEY EXCHANGE PROTOCOL (for E2E encryption)
// ============================================================================

impl CryptoManager {
    /// Perform a key exchange using X25519
    pub fn perform_key_exchange(&self, their_public_key: &str, my_private_key: &str) -> Result<Vec<u8>> {
        use ring::agreement;

        let their_public_bytes = general_purpose::STANDARD.decode(their_public_key)
            .context("Invalid public key encoding")?;

        let my_private_bytes = general_purpose::STANDARD.decode(my_private_key)
            .context("Invalid private key encoding")?;

        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)
            .context("Failed to generate ephemeral private key")?;

        let my_public_key = my_private_key.compute_public_key()
            .context("Failed to compute public key")?;

        agreement::agree_ephemeral(
            my_private_key,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, &their_public_bytes),
            |key_material| {
                let mut shared_secret = vec![0u8; 32];
                shared_secret.copy_from_slice(key_material);
                Ok(shared_secret)
            },
        ).context("Key agreement failed")
    }
}

// ============================================================================
// SECURE STORAGE HELPERS
// ============================================================================

impl CryptoManager {
    /// Encrypt data for secure local storage
    pub fn encrypt_for_storage(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
                .context("Invalid storage key")?
        );

        let mut nonce_bytes = [0u8; 12];
        let mut bytes = nonce_bytes;
        self.rng.fill(&mut bytes)
            .context("Failed to generate nonce")?;
        let nonce_bytes = bytes;

        let mut in_out = data.to_vec();
        sealing_key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_bytes),
            aead::Aad::from(b"storage"),
            &mut in_out
        ).context("Storage encryption failed")?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt data from secure local storage
    pub fn decrypt_from_storage(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }

        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
                .context("Invalid storage key")?
        );

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce: [u8; 12] = nonce_bytes.try_into()
            .context("Invalid nonce")?;

        let mut in_out = ciphertext.to_vec();
        let plaintext = opening_key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(b"storage"),
            &mut in_out
        ).context("Storage decryption failed")?;

        Ok(plaintext.to_vec())
    }
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}