use crate::error::{Result, SteganographyError};
use base64::{engine::general_purpose, Engine as _};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use rand::RngCore;
use std::{fs, path::Path};

/// ChaCha20 encryption key size in bytes
const ENCRYPTION_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes
const NONCE_SIZE: usize = 12;

/// Default repetition factor for error correction
const DEFAULT_REPETITION_FACTOR: usize = 5;

/// Cryptographic engine handling ChaCha20 encryption and repetition coding
pub struct CryptographicEngine {
    repetition_factor: usize,
}

impl CryptographicEngine {
    /// Creates a new cryptographic engine with default settings
    pub fn new() -> Self {
        Self {
            repetition_factor: DEFAULT_REPETITION_FACTOR,
        }
    }

    /// Creates a new cryptographic engine with custom repetition factor
    pub fn with_repetition_factor(repetition_factor: usize) -> Self {
        Self { repetition_factor }
    }

    /// Generates a cryptographically secure random ChaCha20 key
    pub fn generate_encryption_key() -> [u8; ENCRYPTION_KEY_SIZE] {
        let mut encryption_key = [0u8; ENCRYPTION_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut encryption_key);
        encryption_key
    }

    /// Generates a random nonce for ChaCha20 encryption
    fn generate_nonce(&self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Applies repetition coding to data for error correction
    fn apply_repetition_encoding(&self, original_data: &[u8]) -> Result<Vec<u8>> {
        let mut encoded_data = Vec::new();

        // Store original data length as 4-byte header
        encoded_data.extend_from_slice(&(original_data.len() as u32).to_le_bytes());

        // Repeat each byte multiple times for redundancy
        for &data_byte in original_data {
            for _ in 0..self.repetition_factor {
                encoded_data.push(data_byte);
            }
        }

        Ok(encoded_data)
    }

    /// Decodes repetition-encoded data using majority voting
    fn apply_repetition_decoding(&self, encoded_data: &[u8]) -> Result<Vec<u8>> {
        if encoded_data.len() < 4 {
            return Err(SteganographyError::InvalidInput(
                "Encoded data too short for length header".to_string(),
            ));
        }

        // Extract original data length from header
        let original_data_length = u32::from_le_bytes([
            encoded_data[0],
            encoded_data[1],
            encoded_data[2],
            encoded_data[3],
        ]) as usize;

        let expected_encoded_length = 4 + (original_data_length * self.repetition_factor);
        if encoded_data.len() != expected_encoded_length {
            return Err(SteganographyError::InvalidInput(format!(
                "Invalid encoded data length: expected {}, got {}",
                expected_encoded_length,
                encoded_data.len()
            )));
        }

        let mut decoded_data = Vec::new();
        let data_start_index = 4;

        // Decode each byte using majority voting for error correction
        for byte_index in 0..original_data_length {
            let repetition_start = data_start_index + (byte_index * self.repetition_factor);
            let repetition_end = repetition_start + self.repetition_factor;

            if repetition_end > encoded_data.len() {
                return Err(SteganographyError::InvalidInput(format!(
                    "Insufficient repetition data for byte {}",
                    byte_index
                )));
            }

            let repeated_bytes = &encoded_data[repetition_start..repetition_end];

            // Count votes for each possible byte value
            let mut vote_counts = [0u32; 256];
            for &byte_value in repeated_bytes {
                vote_counts[byte_value as usize] += 1;
            }

            // Select the byte value with the most votes
            let (winning_byte_value, _) = vote_counts
                .iter()
                .enumerate()
                .max_by_key(|(_, &vote_count)| vote_count)
                .unwrap();

            decoded_data.push(winning_byte_value as u8);
        }

        Ok(decoded_data)
    }

    /// Encrypts data using ChaCha20 and applies repetition coding for error correction
    pub fn encrypt_with_error_correction(
        &self,
        encryption_key: &[u8; ENCRYPTION_KEY_SIZE],
        plaintext_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Generate a random nonce for this encryption
        let nonce = self.generate_nonce();

        // Create ChaCha20 stream cipher
        let mut cipher = ChaCha20::new(encryption_key.into(), &nonce.into());

        // Encrypt the plaintext data
        let mut ciphertext_data = plaintext_data.to_vec();
        cipher.apply_keystream(&mut ciphertext_data);

        // Prepend nonce to ciphertext for decryption
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext_data);

        // Apply repetition coding for error correction
        let error_corrected_data = self.apply_repetition_encoding(&encrypted_data)?;

        println!(
            "Encryption: {} bytes -> {} bytes with {}x repetition ({:.1}% overhead)",
            encrypted_data.len(),
            error_corrected_data.len(),
            self.repetition_factor,
            (error_corrected_data.len() as f64 / encrypted_data.len() as f64 - 1.0) * 100.0
        );

        Ok(error_corrected_data)
    }

    /// Decrypts data by first applying repetition decoding then ChaCha20 decryption
    pub fn decrypt_with_error_correction(
        &self,
        encryption_key: &[u8; ENCRYPTION_KEY_SIZE],
        error_corrected_data: &[u8],
    ) -> Result<Vec<u8>> {
        // First, apply repetition decoding to correct bit errors
        let encrypted_data = self
            .apply_repetition_decoding(error_corrected_data)
            .map_err(|error| {
                SteganographyError::CryptoError(format!("Repetition decoding failed: {}", error))
            })?;

        println!(
            "Error correction: Recovered {} bytes from {} bytes",
            encrypted_data.len(),
            error_corrected_data.len()
        );

        if encrypted_data.len() < NONCE_SIZE {
            return Err(SteganographyError::CryptoError(
                "Encrypted data too short to contain nonce".to_string(),
            ));
        }

        // Extract nonce and ciphertext
        let nonce = &encrypted_data[..NONCE_SIZE];
        let ciphertext_data = &encrypted_data[NONCE_SIZE..];

        // Create ChaCha20 cipher with the same key and extracted nonce
        let mut cipher = ChaCha20::new(encryption_key.into(), nonce.try_into().unwrap());

        // Decrypt by applying the same keystream
        let mut plaintext_data = ciphertext_data.to_vec();
        cipher.apply_keystream(&mut plaintext_data);

        Ok(plaintext_data)
    }

    /// Saves encryption key to file in base64 format
    pub fn save_key_to_file(
        &self,
        encryption_key: &[u8; ENCRYPTION_KEY_SIZE],
        file_path: &str,
    ) -> Result<()> {
        let base64_encoded_key = general_purpose::STANDARD.encode(encryption_key);
        fs::write(file_path, base64_encoded_key)?;
        Ok(())
    }

    /// Loads encryption key from file or parses from base64 string
    pub fn load_key_from_input(&self, key_input: &str) -> Result<[u8; ENCRYPTION_KEY_SIZE]> {
        let key_data = if Path::new(key_input).exists() {
            fs::read_to_string(key_input)?
        } else {
            key_input.to_string()
        };

        let key_bytes = general_purpose::STANDARD
            .decode(key_data.trim())
            .map_err(|error| SteganographyError::Base64Error(error.to_string()))?;

        if key_bytes.len() != ENCRYPTION_KEY_SIZE {
            return Err(SteganographyError::InvalidInput(format!(
                "Invalid key length: expected {} bytes, got {}",
                ENCRYPTION_KEY_SIZE,
                key_bytes.len()
            )));
        }

        let mut encryption_key = [0u8; ENCRYPTION_KEY_SIZE];
        encryption_key.copy_from_slice(&key_bytes);
        Ok(encryption_key)
    }
}

impl Default for CryptographicEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let crypto_engine = CryptographicEngine::new();
        let encryption_key = CryptographicEngine::generate_encryption_key();
        let test_data = b"Secret message for testing";

        let encrypted_data = crypto_engine
            .encrypt_with_error_correction(&encryption_key, test_data)
            .unwrap();
        let decrypted_data = crypto_engine
            .decrypt_with_error_correction(&encryption_key, &encrypted_data)
            .unwrap();

        assert_eq!(test_data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_repetition_coding_with_errors() {
        let crypto_engine = CryptographicEngine::with_repetition_factor(3);
        let test_data = vec![0x42, 0x73, 0xA5];

        let encoded_data = crypto_engine.apply_repetition_encoding(&test_data).unwrap();
        
        // Simulate bit errors by corrupting some bytes
        let mut corrupted_data = encoded_data;
        corrupted_data[5] = 0xFF; // Corrupt one repetition
        corrupted_data[8] = 0x00; // Corrupt another repetition

        let decoded_data = crypto_engine.apply_repetition_decoding(&corrupted_data).unwrap();
        assert_eq!(test_data, decoded_data);
    }
}
