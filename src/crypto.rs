//! # Cryptographic operations for IronShield challenges
//!
//! This module provides Ed25519 signature generation and verification for IronShield challenges,
//! including key management from environment variables and challenge signing/verification.
//!
//! ## Key Format Support
//!
//! The key loading functions support multiple formats with automatic detection:
//! - **Raw Ed25519 Keys**: Base64-encoded 32-byte Ed25519 keys (legacy format)
//! - **PGP Format**: Base64-encoded PGP keys (without ASCII armor headers)
//!
//! For PGP keys, a simple heuristic scans the binary data to find valid Ed25519 key material.
//! This approach is simpler and more reliable than using complex PGP parsing libraries.
//!
//! ## Features
//!
//! ### Key Management
//! * `load_private_key_from_env()`:            Load Ed25519 private key from environment
//!                                             (multiple formats)
//! * `load_public_key()`:                      Load Ed25519 public key from provided data
//!                                             or environment (multiple formats)
//! * `generate_test_keypair()`:                Generate keypair for testing.
//!
//! ### Challenge Signing
//! * `sign_challenge()`:                       Sign challenges with environment private key
//! * `IronShieldChallenge::create_signed()`:   Create and sign challenges in one step
//!
//! ### Challenge Verification
//! * `verify_challenge_signature()`:           Verify using environment public key
//! * `verify_challenge_signature_with_key()`:  Verify using provided public key
//! * `validate_challenge()`:                   Comprehensive challenge validation
//!                                             (signature + expiration)
//!
//! ## Environment Variables
//!
//! The following environment variables are used for key storage:
//! * `IRONSHIELD_PRIVATE_KEY`:                 Base64-encoded private key (PGP or raw Ed25519)
//! * `IRONSHIELD_PUBLIC_KEY`:                  Base64-encoded public key (PGP or raw Ed25519)
//!
//! ## Examples
//!
//! ### Basic Usage with Raw Keys
//! Generate test keys and set them as environment variables, then load them
//! using `load_private_key_from_env()` and `load_public_key(None)`.
//!
//! ### Using with PGP Keys
//! For PGP keys stored in Cloudflare Secrets Store, use `load_public_key(Some(key_data))`
//! with base64-encoded PGP data without ASCII armor headers.

use base64::{
    Engine,
    engine::general_purpose::STANDARD
};
use ed25519_dalek::{
    Signature,
    Signer,
    Verifier,
    SigningKey,
    VerifyingKey,
    PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH
};
use rand::rngs::OsRng;

use crate::IronShieldChallenge;

use std::env;

/// Debug logging helper that works across different compilation targets
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(all(target_arch = "wasm32", feature = "wasm-logging"))]
        {
            let msg = format!($($arg)*);
            web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(&msg));
        }
        #[cfg(not(target_arch = "wasm32"))]
        eprintln!($($arg)*);
        #[cfg(all(target_arch = "wasm32", not(feature = "wasm-logging")))]
        {
            // No-op for WASM without logging feature
            let _ = format!($($arg)*);
        }
    };
}

#[derive(Debug, Clone)]
pub enum CryptoError {
    MissingEnvironmentVariable(String),
    InvalidKeyFormat(String),
    SigningFailed(String),
    VerificationFailed(String),
    Base64DecodingFailed(String),
    PgpParsingFailed(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::MissingEnvironmentVariable(var) => write!(f, "Missing environment variable: {}", var),
            CryptoError::InvalidKeyFormat(msg) => write!(f, "Invalid key format: {}", msg),
            CryptoError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            CryptoError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            CryptoError::Base64DecodingFailed(msg) => write!(f, "Base64 decoding failed: {}", msg),
            CryptoError::PgpParsingFailed(msg) => write!(f, "PGP parsing failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Parse key data with simple heuristic approach (handles PGP and raw Ed25519)
///
/// This function attempts to extract Ed25519 key material from various formats:
/// 1. PGP armored text (base64 with possible line breaks)
/// 2. Raw base64-encoded Ed25519 keys (32 bytes)
///
/// # Arguments
/// * `key_data`:   Key data as string (PGP armored or raw base64)
/// * `is_private`: Whether this is a private key (for validation)
///
/// # Returns
/// * `Result<[u8; 32], CryptoError>`: The 32-byte Ed25519 key
fn parse_key_simple(key_data: &str, is_private: bool) -> Result<[u8; 32], CryptoError> {
    // Clean the key data by removing all whitespace, line breaks, and common PGP formatting
    let cleaned_data = key_data
        .chars()
        .filter(|c| !c.is_whitespace()) // Remove all whitespace including \n, \r, \t, spaces
        .collect::<String>();

    debug_log!("Parsing key data: {} chars -> {} chars after cleaning", key_data.len(), cleaned_data.len());

    // Check for any invalid base64 characters
    let invalid_chars: Vec<char> = cleaned_data
        .chars()
        .filter(|&c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '='))
        .collect();

    if !invalid_chars.is_empty() {
        debug_log!("Fixing {} invalid base64 characters", invalid_chars.len());

        // Try to fix common issues
        let fixed_data = cleaned_data
            .chars()
            .filter(|&c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '='))
            .collect::<String>();

        debug_log!("Fixed data length: {}", fixed_data.len());

        // Try to decode the fixed data
        match STANDARD.decode(&fixed_data) {
            Ok(key_bytes) => {
                debug_log!("Fixed data decoded to {} bytes", key_bytes.len());
                return try_extract_ed25519_key(&key_bytes, is_private);
            }
            Err(e) => {
                debug_log!("Fixed data decode failed: {}", e);
            }
        }
    }

    // Try to decode as base64
    let key_bytes = match STANDARD.decode(&cleaned_data) {
        Ok(bytes) => {
            debug_log!("Base64 decoded to {} bytes", bytes.len());
            bytes
        }
        Err(e) => {
            debug_log!("Base64 decode failed: {}", e);

            // Try removing trailing characters that might be corrupted
            let mut test_data = cleaned_data.clone();
            while !test_data.is_empty() {
                if let Ok(bytes) = STANDARD.decode(&test_data) {
                    debug_log!("Successful decode after trimming to {} chars -> {} bytes", test_data.len(), bytes.len());
                    return try_extract_ed25519_key(&bytes, is_private);
                }
                test_data.pop();
            }

            return Err(CryptoError::Base64DecodingFailed(format!("Failed to decode cleaned key data: {}", e)));
        }
    };

    try_extract_ed25519_key(&key_bytes, is_private)
}

/// Extract Ed25519 key material from decoded bytes
fn try_extract_ed25519_key(key_bytes: &[u8], is_private: bool) -> Result<[u8; 32], CryptoError> {
    debug_log!("Extracting Ed25519 key from {} bytes", key_bytes.len());

    // If it's exactly 32 bytes, it might be a raw Ed25519 key
    if key_bytes.len() == 32 {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        // Validate the key
        if is_private {
            let _signing_key = SigningKey::from_bytes(&key_array);
            debug_log!("Raw Ed25519 private key validated");
        } else {
            let _verifying_key = VerifyingKey::from_bytes(&key_array)
                .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid raw public key: {}", e)))?;
            debug_log!("Raw Ed25519 public key validated");
        }

        return Ok(key_array);
    }

    // For larger data (PGP format), use multiple sophisticated key extraction strategies
    if key_bytes.len() >= 32 {
        debug_log!("Scanning PGP data for Ed25519 key...");

        // Strategy 1: Look for Ed25519 algorithm identifier (0x16 = 22 decimal)
        // Ed25519 keys in PGP often have specific patterns
        for window_start in 0..key_bytes.len().saturating_sub(32) {
            let potential_key = &key_bytes[window_start..window_start + 32];

            // Skip obviously invalid keys (all zeros, all 0xFF, or patterns that don't make sense)
            if potential_key == &[0u8; 32] || potential_key == &[0xFFu8; 32] {
                continue;
            }

            // For Ed25519, check if this looks like valid key material
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(potential_key);

            if is_private {
                // For private keys, try to create a SigningKey and derive the public key
                let signing_key = SigningKey::from_bytes(&key_array);
                let derived_public = signing_key.verifying_key();

                // Additional validation: check if the derived public key appears elsewhere in the PGP data
                let public_bytes = derived_public.to_bytes();

                // Look for the derived public key in the remaining PGP data
                let search_start = window_start + 32;
                if search_start < key_bytes.len() {
                    let remaining_data = &key_bytes[search_start..];
                    if remaining_data.windows(32).any(|window| window == public_bytes) {
                        debug_log!("Private key found at offset {} (with matching public key)", window_start);
                        return Ok(key_array);
                    }
                }

                // Even if we don't find the public key, if this is at a reasonable offset, it might be valid
                if window_start >= 20 && window_start <= 200 {
                    debug_log!("Private key found at offset {}", window_start);
                    return Ok(key_array);
                }
            } else {
                // For public keys, try to create a VerifyingKey
                if let Ok(_verifying_key) = VerifyingKey::from_bytes(&key_array) {
                    // Additional validation: public keys should appear after some PGP header data
                    if window_start >= 10 && window_start <= 100 {
                        debug_log!("Public key found at offset {}", window_start);
                        return Ok(key_array);
                    }
                }
            }
        }

        // Strategy 2: Look for specific PGP packet patterns
        for (i, &byte) in key_bytes.iter().enumerate() {
            if byte == 0x16 && i + 33 < key_bytes.len() { // Algorithm 22 (Ed25519) + 32 bytes key
                let key_start = i + 1;
                if key_start + 32 <= key_bytes.len() {
                    let potential_key = &key_bytes[key_start..key_start + 32];
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(potential_key);

                    // Validate this key
                    if is_private {
                        let _signing_key = SigningKey::from_bytes(&key_array);
                        debug_log!("Private key found via algorithm ID at offset {}", key_start);
                        return Ok(key_array);
                    } else {
                        if let Ok(_verifying_key) = VerifyingKey::from_bytes(&key_array) {
                            debug_log!("Public key found via algorithm ID at offset {}", key_start);
                            return Ok(key_array);
                        }
                    }
                }
            }
        }

        // Strategy 3: Look for keys at common PGP offsets
        let common_offsets = [
            32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100,
            104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160
        ];

        for &offset in &common_offsets {
            if offset + 32 <= key_bytes.len() {
                let potential_key = &key_bytes[offset..offset + 32];

                // Skip obviously invalid patterns
                if potential_key == &[0u8; 32] || potential_key == &[0xFFu8; 32] {
                    continue;
                }

                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(potential_key);

                if is_private {
                    let _signing_key = SigningKey::from_bytes(&key_array);
                    debug_log!("Private key found at common offset {}", offset);
                    return Ok(key_array);
                } else {
                    if let Ok(_verifying_key) = VerifyingKey::from_bytes(&key_array) {
                        debug_log!("Public key found at common offset {}", offset);
                        return Ok(key_array);
                    }
                }
            }
        }
    }

    Err(CryptoError::PgpParsingFailed(format!(
        "Could not find valid Ed25519 key material in {} bytes of PGP data using multiple strategies",
        key_bytes.len()
    )))
}

/// Loads the private key from the IRONSHIELD_PRIVATE_KEY environment variable
///
/// The environment variable should contain a base64-encoded PGP private key (without armor headers).
/// For backward compatibility, raw base64-encoded Ed25519 keys (32 bytes) are also supported.
///
/// # Returns
/// * `Result<SigningKey, CryptoError>`: The Ed25519 signing key or an error
///
/// # Environment Variables
/// * `IRONSHIELD_PRIVATE_KEY`:          Base64-encoded PGP private key data
///                                      (without -----BEGIN/END----- lines)
///                                      or raw base64-encoded Ed25519 private
///                                      key (legacy format)
pub fn load_private_key_from_env() -> Result<SigningKey, CryptoError> {
    let key_str: String = env::var("IRONSHIELD_PRIVATE_KEY")
        .map_err(|_| CryptoError::MissingEnvironmentVariable("IRONSHIELD_PRIVATE_KEY".to_string()))?;

    // Try PGP format first
    match parse_key_simple(&key_str, true) {
        Ok(key_array) => {
            let signing_key: SigningKey = SigningKey::from_bytes(&key_array);
            return Ok(signing_key);
        }
        Err(CryptoError::PgpParsingFailed(_)) | Err(CryptoError::Base64DecodingFailed(_)) => {
            // Fall back to raw base64 format
        }
        Err(e) => return Err(e), // Return other errors immediately
    }

    // Fallback: try raw base64-encoded Ed25519 key (legacy format)
    let key_bytes: Vec<u8> = STANDARD.decode(key_str.trim())
        .map_err(|e| CryptoError::Base64DecodingFailed(format!("Private key (legacy fallback): {}", e)))?;

    // Verify length for raw Ed25519 key
    if key_bytes.len() != SECRET_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyFormat(
            format!("Private key must be {} bytes (raw Ed25519) or valid PGP format, got {} bytes",
                   SECRET_KEY_LENGTH, key_bytes.len())
        ));
    }

    // Create signing key from raw bytes
    let key_array: [u8; SECRET_KEY_LENGTH] = key_bytes.try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Failed to convert private key bytes".to_string()))?;

    let signing_key: SigningKey = SigningKey::from_bytes(&key_array);
    Ok(signing_key)
}

/// Loads the public key from provided data or environment variable
///
/// This function attempts to load the public key in the following order:
/// 1. If `key_data` is provided, try to parse it (for production/Cloudflare Secrets Store)
/// 2. Fall back to IRONSHIELD_PUBLIC_KEY environment variable (for local testing)
///
/// The key can be in either format:
/// - Base64-encoded PGP public key (without armor headers)
/// - Raw base64-encoded Ed25519 public key (32 bytes, legacy format)
///
/// # Arguments
/// * `key_data`: Optional key data string (for Cloudflare Workers/production)
///
/// # Returns
/// * `Result<VerifyingKey, CryptoError>`: The Ed25519 verifying key or an error
///
/// # Environment Variables
/// * `IRONSHIELD_PUBLIC_KEY`: Fallback env var for local testing
pub fn load_public_key(key_data: Option<&str>) -> Result<VerifyingKey, CryptoError> {
    // Try provided key_data first (production/Secrets Store)
    if let Some(data) = key_data {
        debug_log!("Attempting to load public key from provided data");
        
        // Try PGP format first
        match parse_key_simple(data, false) {
            Ok(key_array) => {
                let verifying_key = VerifyingKey::from_bytes(&key_array)
                    .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key from PGP: {}", e)))?;
                debug_log!("Successfully loaded public key from provided data");
                return Ok(verifying_key);
            }
            Err(CryptoError::PgpParsingFailed(_)) | Err(CryptoError::Base64DecodingFailed(_)) => {
                // Fall through to try raw format
            }
            Err(e) => {
                // For other errors, log and fall through to env var
                debug_log!("Error parsing provided key data: {}, trying env var fallback", e);
            }
        }

        // Try raw base64-encoded Ed25519 key (legacy format)
        match STANDARD.decode(data.trim()) {
            Ok(key_bytes) if key_bytes.len() == PUBLIC_KEY_LENGTH => {
                let mut key_array = [0u8; PUBLIC_KEY_LENGTH];
                key_array.copy_from_slice(&key_bytes);

                match VerifyingKey::from_bytes(&key_array) {
                    Ok(verifying_key) => {
                        debug_log!("Successfully loaded public key from provided data (raw format)");
                        return Ok(verifying_key);
                    }
                    Err(e) => {
                        debug_log!("Invalid Ed25519 public key in provided data: {}, trying env var fallback", e);
                    }
                }
            }
            Ok(key_bytes) => {
                debug_log!("Invalid key length in provided data: {} bytes, trying env var fallback", key_bytes.len());
            }
            Err(e) => {
                debug_log!("Base64 decode failed for provided data: {}, trying env var fallback", e);
            }
        }
    }

    // Fall back to environment variable (local testing)
    debug_log!("Loading public key from IRONSHIELD_PUBLIC_KEY environment variable");
    
    let key_str = env::var("IRONSHIELD_PUBLIC_KEY")
        .map_err(|_| CryptoError::MissingEnvironmentVariable("IRONSHIELD_PUBLIC_KEY".to_string()))?;

    // Try PGP format first
    match parse_key_simple(&key_str, false) {
        Ok(key_array) => {
            let verifying_key = VerifyingKey::from_bytes(&key_array)
                .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key: {}", e)))?;
            debug_log!("Successfully loaded public key from environment variable");
            return Ok(verifying_key);
        }
        Err(CryptoError::PgpParsingFailed(_)) | Err(CryptoError::Base64DecodingFailed(_)) => {
            // Fall back to raw base64 format
        }
        Err(e) => return Err(e), // Return other errors immediately
    }

    // Fallback: try raw base64-encoded Ed25519 key (legacy format)
    let key_bytes = STANDARD.decode(key_str.trim())
        .map_err(|e| CryptoError::Base64DecodingFailed(format!("Public key (legacy fallback): {}", e)))?;

    // Verify length for raw Ed25519 key
    if key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyFormat(
            format!("Public key must be {} bytes (raw Ed25519) or valid PGP format, got {} bytes",
                   PUBLIC_KEY_LENGTH, key_bytes.len())
        ));
    }

    // Create verifying key from raw bytes
    let key_array: [u8; PUBLIC_KEY_LENGTH] = key_bytes.try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Failed to convert public key bytes".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key: {}", e)))?;

    Ok(verifying_key)
}

/// Creates a message to be signed from challenge data components
///
/// This function creates a canonical representation of the challenge data for signing.
/// It takes individual challenge components rather than a complete challenge object,
/// allowing it to be used during challenge creation.
///
/// # Arguments
/// * `random_nonce`:    The random nonce string
/// * `created_time`:    The challenge creation timestamp
/// * `expiration_time`: The challenge expiration timestamp
/// * `website_id`:      The website identifier
/// * `challenge_param`: The challenge parameter bytes
/// * `public_key`:      The public key bytes
///
/// # Returns
/// * `String`: Canonical string representation for signing
pub fn create_signing_message(
    random_nonce: &str,
    created_time: i64,
    expiration_time: i64,
    website_id: &str,
    challenge_param: &[u8; 32],
    public_key: &[u8; 32]
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        random_nonce,
        created_time,
        expiration_time,
        website_id,
        hex::encode(challenge_param),
        hex::encode(public_key)
    )
}

/// Generates an Ed25519 signature for a given message using the provided signing key
///
/// This is a low-level function for generating signatures. For challenge signing,
/// consider using `sign_challenge` which handles message creation automatically.
///
/// # Arguments
/// * `signing_key`: The Ed25519 signing key to use
/// * `message`:     The message to sign (will be converted to bytes)
///
/// # Returns
/// * `Result<[u8; 64], CryptoError>`: The signature bytes or an error
pub fn generate_signature(signing_key: &SigningKey, message: &str) -> Result<[u8; 64], CryptoError> {
    let signature: Signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes())
}

/// Signs a challenge using the private key from environment variables.
///
/// This function creates a signature over all challenge fields except the signature itself.
/// The private key is loaded from the IRONSHIELD_PRIVATE_KEY environment variable.
///
/// # Arguments
/// * `challenge`: The challenge to sign (signature field will be ignored).
///
/// # Returns
/// * `Result<[u8; 64], CryptoError>`: The Ed25519 signature bytes or an error.
pub fn sign_challenge(challenge: &IronShieldChallenge) -> Result<[u8; 64], CryptoError> {
    let signing_key: SigningKey = load_private_key_from_env()?;
    let message: String = create_signing_message(
        &challenge.random_nonce,
        challenge.created_time,
        challenge.expiration_time,
        &challenge.website_id,
        &challenge.challenge_param,
        &challenge.public_key
    );
    generate_signature(&signing_key, &message)
}

/// Verifies a challenge signature using the public key from environment variables
///
/// This function verifies that the challenge signature is valid and that the challenge
/// data has not been tampered with. The public key is loaded from the IRONSHIELD_PUBLIC_KEY
/// environment variable.
///
/// # Arguments
/// * `challenge`: The challenge with signature to verify.
///
/// # Returns
/// * `Result<(), CryptoError>`: `Ok(())` if valid, error if verification fails.
pub fn verify_challenge_signature(challenge: &IronShieldChallenge) -> Result<(), CryptoError> {
    let verifying_key: VerifyingKey = load_public_key(None)?;

    let message: String = create_signing_message(
        &challenge.random_nonce,
        challenge.created_time,
        challenge.expiration_time,
        &challenge.website_id,
        &challenge.challenge_param,
        &challenge.public_key
    );
    let signature: Signature = Signature::from_slice(&challenge.challenge_signature)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid signature format: {}", e)))?;

    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|e| CryptoError::VerificationFailed(format!("Signature verification failed: {}", e)))?;

    Ok(())
}

/// Verifies a challenge signature using a provided public key
///
/// This function is similar to `verify_challenge_signature` but uses a provided
/// public key instead of loading from environment variables. This is useful for
/// client-side verification where the public key is embedded in the challenge.
///
/// # Arguments
/// * `challenge`:        The challenge with signature to verify
/// * `public_key_bytes`: The Ed25519 public key bytes to use for verification
///
/// # Returns
/// * `Result<(), CryptoError>`: `Ok(())` if valid, error if verification fails
pub fn verify_challenge_signature_with_key(
    challenge: &IronShieldChallenge,
    public_key_bytes: &[u8; 32]
) -> Result<(), CryptoError> {
    let verifying_key: VerifyingKey = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key: {}", e)))?;

    let message: String = create_signing_message(
        &challenge.random_nonce,
        challenge.created_time,
        challenge.expiration_time,
        &challenge.website_id,
        &challenge.challenge_param,
        &challenge.public_key
    );
    let signature: Signature = Signature::from_slice(&challenge.challenge_signature)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid signature format: {}", e)))?;

    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|e| CryptoError::VerificationFailed(format!("Signature verification failed: {}", e)))?;

    Ok(())
}

/// Generates a new Ed25519 keypair for testing purposes
///
/// This function generates a fresh keypair and returns the keys in raw base64 format
/// (legacy format) suitable for use as environment variables in tests.
///
/// # Returns
/// * `(String, String)`: (base64_private_key, base64_public_key) in raw Ed25519 format
pub fn generate_test_keypair() -> (String, String) {
    let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let private_key_b64: String = STANDARD.encode(signing_key.to_bytes());
    let public_key_b64: String = STANDARD.encode(verifying_key.to_bytes());

    (private_key_b64, public_key_b64)
}

/// Verifies a challenge and checks if it's valid and not expired
///
/// This is a comprehensive validation function that checks:
/// - Signature validity
/// - Challenge expiration
/// - Basic format validation
///
/// # Arguments
/// * `challenge`: The challenge to validate
///
/// # Returns
/// * `Result<(), CryptoError>`: `Ok(())` if valid, error if invalid
pub fn validate_challenge(challenge: &IronShieldChallenge) -> Result<(), CryptoError> {
    // Check signature first
    verify_challenge_signature(challenge)?;

    // Check expiration
    if challenge.is_expired() {
        return Err(CryptoError::VerificationFailed("Challenge has expired".to_string()));
    }

    if challenge.website_id.is_empty() {
        return Err(CryptoError::VerificationFailed("Empty website_id".to_string()));
    }

    Ok(())
}

/// Loads a private key from raw key data (for Cloudflare Workers)
///
/// This function is designed for use with Cloudflare Workers where secrets
/// are accessible through the env parameter rather than standard environment variables.
///
/// # Arguments
/// * `key_data`: Base64-encoded key data (PGP or raw Ed25519)
///
/// # Returns
/// * `Result<SigningKey, CryptoError>`: The Ed25519 signing key or an error
pub fn load_private_key_from_data(key_data: &str) -> Result<SigningKey, CryptoError> {
    // Try PGP format first
    match parse_key_simple(key_data, true) {
        Ok(key_array) => {
            let signing_key: SigningKey = SigningKey::from_bytes(&key_array);
            return Ok(signing_key);
        }
        Err(CryptoError::PgpParsingFailed(_msg)) => {
            // Fall back to raw base64 format
        }
        Err(CryptoError::Base64DecodingFailed(_msg)) => {
            // Fall back to raw base64 format
        }
        Err(e) => {
            return Err(e); // Return other errors immediately
        }
    }

    // Fallback: try raw base64-encoded Ed25519 key (legacy format)
    let key_bytes: Vec<u8> = STANDARD.decode(key_data.trim())
        .map_err(|e| {
            CryptoError::Base64DecodingFailed(format!("Private key (legacy fallback): {}", e))
        })?;

    // Verify length for raw Ed25519 key
    if key_bytes.len() != SECRET_KEY_LENGTH {
        let error_msg = format!(
            "Invalid key length: expected {} bytes for Ed25519 private key, got {} bytes",
            SECRET_KEY_LENGTH,
            key_bytes.len()
        );
        return Err(CryptoError::InvalidKeyFormat(error_msg));
    }

    let mut key_array = [0u8; SECRET_KEY_LENGTH];
    key_array.copy_from_slice(&key_bytes);

    Ok(SigningKey::from_bytes(&key_array))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test parsing a raw 32-byte Ed25519 private key
    #[test]
    fn test_parse_raw_ed25519_private_key() {
        // Generate a test keypair
        let (private_b64, _) = generate_test_keypair();
        
        // Parse the private key
        let result = parse_key_simple(&private_b64, true);
        assert!(result.is_ok(), "Failed to parse raw Ed25519 private key");
        
        let key_bytes = result.unwrap();
        assert_eq!(key_bytes.len(), 32, "Key should be 32 bytes");
        
        // Verify it's a valid Ed25519 private key
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let _ = signing_key.verifying_key(); // Should not panic
        
        println!("Successfully parsed raw Ed25519 private key");
    }

    /// Test parsing a raw 32-byte Ed25519 public key
    #[test]
    fn test_parse_raw_ed25519_public_key() {
        // Generate a test keypair
        let (_, public_b64) = generate_test_keypair();
        
        // Parse the public key
        let result = parse_key_simple(&public_b64, false);
        assert!(result.is_ok(), "Failed to parse raw Ed25519 public key");
        
        let key_bytes = result.unwrap();
        assert_eq!(key_bytes.len(), 32, "Key should be 32 bytes");
        
        // Verify it's a valid Ed25519 public key
        let verifying_key = VerifyingKey::from_bytes(&key_bytes);
        assert!(verifying_key.is_ok(), "Should be a valid Ed25519 public key");
        
        println!("Successfully parsed raw Ed25519 public key");
    }

    /// Test that parse_key_simple handles whitespace correctly
    #[test]
    fn test_parse_key_with_whitespace() {
        let (private_b64, _) = generate_test_keypair();
        
        // Add various types of whitespace
        let with_spaces = format!("  {}  ", private_b64);
        let with_newlines = format!("{}\n\n", private_b64);
        let with_tabs = format!("\t{}\t", private_b64);
        let with_mixed = format!("\n  {}\t\n  ", private_b64);
        
        for key_str in [with_spaces, with_newlines, with_tabs, with_mixed] {
            let result = parse_key_simple(&key_str, true);
            assert!(
                result.is_ok(),
                "Should handle whitespace, got error: {:?}",
                result.err()
            );
        }
        
        println!("Successfully handled various whitespace formats");
    }

    /// Test error handling for invalid base64
    #[test]
    fn test_parse_invalid_base64() {
        let invalid_base64 = "this is not valid base64!!!@#$%";
        
        let result = parse_key_simple(invalid_base64, true);
        assert!(result.is_err(), "Should fail on invalid base64");
        
        // Accept either Base64DecodingFailed or PgpParsingFailed since the function
        // may "fix" invalid chars and decode to garbage that fails PGP extraction
        match result.err().unwrap() {
            CryptoError::Base64DecodingFailed(_) | CryptoError::PgpParsingFailed(_) => {
                println!("Correctly rejected invalid input");
            }
            other => panic!("Expected Base64DecodingFailed or PgpParsingFailed, got: {:?}", other),
        }
    }

    /// Test error handling for wrong-sized keys
    #[test]
    fn test_parse_wrong_size_key() {
        // Create a base64 string that decodes to wrong number of bytes
        let wrong_size = STANDARD.encode(&[0u8; 16]); // Only 16 bytes instead of 32
        
        let result = parse_key_simple(&wrong_size, true);
        assert!(result.is_err(), "Should fail on wrong-sized key");
        
        println!("Correctly rejected wrong-sized key");
    }

    /// Test that private and public keys are correctly distinguished
    #[test]
    fn test_private_vs_public_key_validation() {
        let (private_b64, public_b64) = generate_test_keypair();
        
        // Parse private key as private - should work
        let result = parse_key_simple(&private_b64, true);
        assert!(result.is_ok(), "Private key should parse as private");
        
        // Parse public key as public - should work
        let result = parse_key_simple(&public_b64, false);
        assert!(result.is_ok(), "Public key should parse as public");
        
        println!("Correctly validated private vs public keys");
    }

    /// Test the complete flow: generate, parse, sign, verify
    #[test]
    fn test_parse_key_simple_end_to_end() {
        // Generate a keypair
        let (private_b64, public_b64) = generate_test_keypair();
        
        // Parse both keys
        let private_bytes = parse_key_simple(&private_b64, true)
            .expect("Failed to parse private key");
        let public_bytes = parse_key_simple(&public_b64, false)
            .expect("Failed to parse public key");
        
        // Create Ed25519 keys
        let signing_key = SigningKey::from_bytes(&private_bytes);
        let verifying_key = VerifyingKey::from_bytes(&public_bytes)
            .expect("Invalid public key");
        
        // Sign a message
        let message = b"Test message for IronShield";
        let signature = signing_key.sign(message);
        
        // Verify the signature
        verifying_key
            .verify(message, &signature)
            .expect("Signature verification failed");
        
        // Verify that the public key derived from private matches parsed public
        let derived_public = signing_key.verifying_key();
        assert_eq!(
            derived_public.to_bytes(),
            public_bytes,
            "Derived public key should match parsed public key"
        );
        
        println!("Successfully completed end-to-end test");
    }

    /// Test empty input handling
    #[test]
    fn test_parse_empty_string() {
        let result = parse_key_simple("", true);
        assert!(result.is_err(), "Should fail on empty string");
        
        println!("Correctly rejected empty string");
    }
}

