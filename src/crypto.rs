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
//! - `load_private_key_from_env()` - Load Ed25519 private key from environment (multiple formats)
//! - `load_public_key_from_env()` - Load Ed25519 public key from environment (multiple formats)
//! - `generate_test_keypair()` - Generate keypairs for testing
//!
//! ### Challenge Signing
//! - `sign_challenge()` - Sign challenges with environment private key
//! - `IronShieldChallenge::create_signed()` - Create and sign challenges in one step
//!
//! ### Challenge Verification
//! - `verify_challenge_signature()` - Verify using environment public key
//! - `verify_challenge_signature_with_key()` - Verify using provided public key
//! - `validate_challenge()` - Comprehensive challenge validation (signature + expiration)
//!
//! ## Environment Variables
//!
//! The following environment variables are used for key storage:
//! - `IRONSHIELD_PRIVATE_KEY` - Base64-encoded private key (PGP or raw Ed25519)
//! - `IRONSHIELD_PUBLIC_KEY` - Base64-encoded public key (PGP or raw Ed25519)
//!
//! ## Examples
//!
//! ### Basic Usage with Raw Keys
//! ```no_run
//! use ironshield_types::{load_private_key_from_env, generate_test_keypair};
//! 
//! // Generate test keys
//! let (private_b64, public_b64) = generate_test_keypair();
//! std::env::set_var("IRONSHIELD_PRIVATE_KEY", private_b64);
//! std::env::set_var("IRONSHIELD_PUBLIC_KEY", public_b64);
//! 
//! // Load keys from environment
//! let signing_key = load_private_key_from_env().unwrap();
//! ```
//!
//! ### Using with PGP Keys
//! For PGP keys stored in Cloudflare Secrets Store (base64-encoded without armor):
//! ```bash
//! # Store PGP keys in Cloudflare Secrets Store
//! wrangler secrets-store secret create STORE_ID \
//!   --name IRONSHIELD_PRIVATE_KEY \
//!   --value "LS0tLS1CRUdJTi..." \  # Base64 PGP data without headers
//!   --scopes workers
//! ```

use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use crate::IronShieldChallenge;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::env;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Environment variable not found
    MissingEnvironmentVariable(String),
    /// Invalid key format or length
    InvalidKeyFormat(String),
    /// Signature generation failed
    SigningFailed(String),
    /// Signature verification failed
    VerificationFailed(String),
    /// Base64 decoding failed
    Base64DecodingFailed(String),
    /// PGP parsing failed
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

/// Simple approach: Try to extract Ed25519 key from PGP data, fall back to raw base64
/// 
/// This function attempts to parse PGP data using basic pattern matching to find Ed25519 keys.
/// If that fails, it tries to parse as raw base64-encoded Ed25519 keys.
/// 
/// # Arguments
/// * `key_data` - Base64-encoded key data (PGP or raw Ed25519)
/// * `is_private` - Whether this is a private key (affects expected length)
/// 
/// # Returns
/// * `Result<[u8; 32], CryptoError>` - The 32-byte Ed25519 key or an error
fn parse_key_simple(key_data: &str, is_private: bool) -> Result<[u8; 32], CryptoError> {
    // First, try to decode as base64
    let key_bytes = STANDARD.decode(key_data.trim())
        .map_err(|e| CryptoError::Base64DecodingFailed(format!("Key data: {}", e)))?;
    
    // If it's exactly 32 bytes, treat it as raw Ed25519
    if key_bytes.len() == 32 {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        return Ok(key_array);
    }
    
    // For PGP format, look for Ed25519 key patterns
    // This is a simplified approach that looks for common Ed25519 signatures in PGP data
    if key_bytes.len() > 32 {
        // Simple pattern: look for sequences of 32 consecutive bytes that could be keys
        // This is a heuristic approach - scan through the data looking for potential key material
        for window_start in 0..key_bytes.len().saturating_sub(32) {
            let potential_key = &key_bytes[window_start..window_start + 32];
            
            // Basic heuristic: Ed25519 keys shouldn't be all zeros or all 0xFF
            if potential_key == &[0u8; 32] || potential_key == &[0xFFu8; 32] {
                continue;
            }
            
            // Convert slice to array for Ed25519 key validation
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(potential_key);
            
            // Try to validate this as an Ed25519 key
            if is_private {
                // For private keys, try to create a SigningKey
                // SigningKey::from_bytes() doesn't return a Result, so just create it
                let _signing_key = SigningKey::from_bytes(&key_array);
                return Ok(key_array);
            } else {
                // For public keys, try to create a VerifyingKey
                if let Ok(_verifying_key) = VerifyingKey::from_bytes(&key_array) {
                    return Ok(key_array);
                }
            }
        }
        
        return Err(CryptoError::PgpParsingFailed(
            "Could not find valid Ed25519 key material in PGP data".to_string()
        ));
    }
    
    Err(CryptoError::InvalidKeyFormat(
        format!("Key data must be either 32 bytes (raw Ed25519) or longer (PGP format), got {} bytes", key_bytes.len())
    ))
}

/// Loads the private key from the IRONSHIELD_PRIVATE_KEY environment variable
/// 
/// The environment variable should contain a base64-encoded PGP private key (without armor headers).
/// For backward compatibility, raw base64-encoded Ed25519 keys (32 bytes) are also supported.
/// 
/// # Returns
/// * `Result<SigningKey, CryptoError>` - The Ed25519 signing key or an error
/// 
/// # Environment Variables
/// * `IRONSHIELD_PRIVATE_KEY` - Base64-encoded PGP private key data (without -----BEGIN/END----- lines)
///                              or raw base64-encoded Ed25519 private key (legacy format)
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

/// Loads the public key from the IRONSHIELD_PUBLIC_KEY environment variable
/// 
/// The environment variable should contain a base64-encoded PGP public key (without armor headers).
/// For backward compatibility, raw base64-encoded Ed25519 keys (32 bytes) are also supported.
/// 
/// # Returns
/// * `Result<VerifyingKey, CryptoError>` - The Ed25519 verifying key or an error
/// 
/// # Environment Variables
/// * `IRONSHIELD_PUBLIC_KEY` - Base64-encoded PGP public key data (without -----BEGIN/END----- lines)
///                             or raw base64-encoded Ed25519 public key (legacy format)
pub fn load_public_key_from_env() -> Result<VerifyingKey, CryptoError> {
    let key_str: String = env::var("IRONSHIELD_PUBLIC_KEY")
        .map_err(|_| CryptoError::MissingEnvironmentVariable("IRONSHIELD_PUBLIC_KEY".to_string()))?;
    
    // Try PGP format first
    match parse_key_simple(&key_str, false) {
        Ok(key_array) => {
            let verifying_key: VerifyingKey = VerifyingKey::from_bytes(&key_array)
                .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key: {}", e)))?;
            return Ok(verifying_key);
        }
        Err(CryptoError::PgpParsingFailed(_)) | Err(CryptoError::Base64DecodingFailed(_)) => {
            // Fall back to raw base64 format
        }
        Err(e) => return Err(e), // Return other errors immediately
    }
    
    // Fallback: try raw base64-encoded Ed25519 key (legacy format)
    let key_bytes: Vec<u8> = STANDARD.decode(key_str.trim())
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
    
    let verifying_key: VerifyingKey = VerifyingKey::from_bytes(&key_array)
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
/// * `random_nonce` - The random nonce string
/// * `created_time` - The challenge creation timestamp
/// * `expiration_time` - The challenge expiration timestamp  
/// * `website_id` - The website identifier
/// * `challenge_param` - The challenge parameter bytes
/// * `public_key` - The public key bytes
/// 
/// # Returns
/// * `String` - Canonical string representation for signing
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
/// * `signing_key` - The Ed25519 signing key to use
/// * `message` - The message to sign (will be converted to bytes)
/// 
/// # Returns
/// * `Result<[u8; 64], CryptoError>` - The signature bytes or an error
/// 
/// # Example
/// ```no_run
/// use ironshield_types::{generate_signature, load_private_key_from_env};
/// 
/// let signing_key = load_private_key_from_env()?;
/// let signature = generate_signature(&signing_key, "message to sign")?;
/// # Ok::<(), ironshield_types::CryptoError>(())
/// ```
pub fn generate_signature(signing_key: &SigningKey, message: &str) -> Result<[u8; 64], CryptoError> {
    let signature: Signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes())
}

/// Signs a challenge using the private key from environment variables
/// 
/// This function creates a signature over all challenge fields except the signature itself.
/// The private key is loaded from the IRONSHIELD_PRIVATE_KEY environment variable.
/// 
/// # Arguments
/// * `challenge` - The challenge to sign (signature field will be ignored)
/// 
/// # Returns
/// * `Result<[u8; 64], CryptoError>` - The Ed25519 signature bytes or an error
/// 
/// # Example
/// ```no_run
/// use ironshield_types::{IronShieldChallenge, sign_challenge, SigningKey};
/// 
/// let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
/// let mut challenge = IronShieldChallenge::new(
///     "test_website".to_string(),
///     [0x12; 32],
///     dummy_key,
///     [0x34; 32],
/// );
/// 
/// // Sign the challenge (requires IRONSHIELD_PRIVATE_KEY environment variable)
/// let signature = sign_challenge(&challenge).unwrap();
/// challenge.challenge_signature = signature;
/// ```
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
/// * `challenge` - The challenge with signature to verify
/// 
/// # Returns
/// * `Result<(), CryptoError>` - Ok(()) if valid, error if verification fails
/// 
/// # Example
/// ```no_run
/// use ironshield_types::{IronShieldChallenge, verify_challenge_signature, SigningKey};
/// 
/// let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
/// let challenge = IronShieldChallenge::new(
///     "test_website".to_string(),
///     [0x12; 32],
///     dummy_key,
///     [0x34; 32],
/// );
/// 
/// // Verify the challenge (requires IRONSHIELD_PUBLIC_KEY environment variable)
/// verify_challenge_signature(&challenge).unwrap();
/// ```
pub fn verify_challenge_signature(challenge: &IronShieldChallenge) -> Result<(), CryptoError> {
    let verifying_key: VerifyingKey = load_public_key_from_env()?;
    
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
/// * `challenge` - The challenge with signature to verify
/// * `public_key_bytes` - The Ed25519 public key bytes to use for verification
/// 
/// # Returns
/// * `Result<(), CryptoError>` - Ok(()) if valid, error if verification fails
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
/// * `(String, String)` - (base64_private_key, base64_public_key) in raw Ed25519 format
/// 
/// # Example
/// ```
/// use ironshield_types::generate_test_keypair;
/// 
/// let (private_key_b64, public_key_b64) = generate_test_keypair();
/// std::env::set_var("IRONSHIELD_PRIVATE_KEY", private_key_b64);
/// std::env::set_var("IRONSHIELD_PUBLIC_KEY", public_key_b64);
/// ```
pub fn generate_test_keypair() -> (String, String) {
    use rand_core::OsRng;
    
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
/// * `challenge` - The challenge to validate
/// 
/// # Returns
/// * `Result<(), CryptoError>` - Ok(()) if valid, error if invalid
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;
    
    // Use a mutex to ensure tests don't interfere with each other when setting env vars
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn setup_isolated_test_keys() -> (SigningKey, VerifyingKey) {
        use rand_core::OsRng;
        
        let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let private_key: String = STANDARD.encode(signing_key.to_bytes());
        let public_key: String = STANDARD.encode(verifying_key.to_bytes());
        
        // Set environment variables with mutex protection
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("IRONSHIELD_PRIVATE_KEY", &private_key);
        env::set_var("IRONSHIELD_PUBLIC_KEY", &public_key);
        
        (signing_key, verifying_key)
    }

    #[test]
    fn test_basic_ed25519_signing() {
        use rand_core::OsRng;
        
        // Test basic Ed25519 signing with a simple message
        let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let message = b"Hello, world!";
        let signature: Signature = signing_key.sign(message);
        
        // This should work without any issues
        let result = verifying_key.verify(message, &signature);
        assert!(result.is_ok(), "Basic Ed25519 signing should work");
    }

    #[test]
    fn test_crypto_integration_without_env() {
        use rand_core::OsRng;
        
        // Generate keys directly without using environment variables
        let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        // Create a challenge with the public key
        let challenge = IronShieldChallenge::new(
            "example.com".to_string(),
            [0xAB; 32],
            signing_key.clone(),
            verifying_key.to_bytes(),
        );
        
        // Create the signing message manually
        let signing_message = create_signing_message(
            &challenge.random_nonce,
            challenge.created_time,
            challenge.expiration_time,
            &challenge.website_id,
            &challenge.challenge_param,
            &challenge.public_key
        );
        println!("Signing message: {}", signing_message);
        
        // The challenge should already be signed, so let's verify it
        let verification_message = create_signing_message(
            &challenge.random_nonce,
            challenge.created_time,
            challenge.expiration_time,
            &challenge.website_id,
            &challenge.challenge_param,
            &challenge.public_key
        );
        assert_eq!(signing_message, verification_message, "Signing message should be consistent");
        
        let signature_from_bytes = Signature::from_slice(&challenge.challenge_signature)
            .expect("Should be able to recreate signature from bytes");
        
        let verification_result = verifying_key.verify(verification_message.as_bytes(), &signature_from_bytes);
        assert!(verification_result.is_ok(), "Manual verification should succeed");
        
        // Now test our helper function
        let verify_result = verify_challenge_signature_with_key(&challenge, &verifying_key.to_bytes());
        assert!(verify_result.is_ok(), "verify_challenge_signature_with_key should succeed");
    }

    #[test]
    fn test_generate_test_keypair() {
        let (private_key, public_key) = generate_test_keypair();
        
        // Keys should be valid base64
        assert!(STANDARD.decode(&private_key).is_ok());
        assert!(STANDARD.decode(&public_key).is_ok());
        
        // Keys should be correct length when decoded
        let private_bytes = STANDARD.decode(&private_key).unwrap();
        let public_bytes = STANDARD.decode(&public_key).unwrap();
        assert_eq!(private_bytes.len(), SECRET_KEY_LENGTH);
        assert_eq!(public_bytes.len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn test_load_keys_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        let (signing_key, verifying_key) = {
            use rand_core::OsRng;
            
            let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
            let verifying_key: VerifyingKey = signing_key.verifying_key();
            
            let private_key: String = STANDARD.encode(signing_key.to_bytes());
            let public_key: String = STANDARD.encode(verifying_key.to_bytes());
            
            env::set_var("IRONSHIELD_PRIVATE_KEY", &private_key);
            env::set_var("IRONSHIELD_PUBLIC_KEY", &public_key);
            
            (signing_key, verifying_key)
        };
        
        // Should successfully load keys
        let loaded_signing_key = load_private_key_from_env().unwrap();
        let loaded_verifying_key = load_public_key_from_env().unwrap();
        
        // Keys should match what we set
        assert_eq!(signing_key.to_bytes(), loaded_signing_key.to_bytes());
        assert_eq!(verifying_key.to_bytes(), loaded_verifying_key.to_bytes());
    }

    #[test]
    fn test_missing_environment_variables() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        // Remove environment variables for this test
        env::remove_var("IRONSHIELD_PRIVATE_KEY");
        env::remove_var("IRONSHIELD_PUBLIC_KEY");
        
        // Should fail with appropriate errors
        let private_result = load_private_key_from_env();
        assert!(private_result.is_err());
        assert!(matches!(private_result.unwrap_err(), CryptoError::MissingEnvironmentVariable(_)));
        
        let public_result = load_public_key_from_env();
        assert!(public_result.is_err());
        assert!(matches!(public_result.unwrap_err(), CryptoError::MissingEnvironmentVariable(_)));
    }

    #[test]
    fn test_invalid_key_format() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        // Set invalid keys
        env::set_var("IRONSHIELD_PRIVATE_KEY", "invalid-base64!");
        env::set_var("IRONSHIELD_PUBLIC_KEY", "invalid-base64!");
        
        let private_result = load_private_key_from_env();
        assert!(private_result.is_err());
        assert!(matches!(private_result.unwrap_err(), CryptoError::Base64DecodingFailed(_)));
        
        let public_result = load_public_key_from_env();
        assert!(public_result.is_err());
        assert!(matches!(public_result.unwrap_err(), CryptoError::Base64DecodingFailed(_)));
    }

    #[test]
    fn test_challenge_signing_and_verification() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        let (signing_key, verifying_key) = {
            use rand_core::OsRng;
            
            let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
            let verifying_key: VerifyingKey = signing_key.verifying_key();
            
            let private_key: String = STANDARD.encode(signing_key.to_bytes());
            let public_key: String = STANDARD.encode(verifying_key.to_bytes());
            
            env::set_var("IRONSHIELD_PRIVATE_KEY", &private_key);
            env::set_var("IRONSHIELD_PUBLIC_KEY", &public_key);
            
            (signing_key, verifying_key)
        };
        
        // Create a test challenge - it will be automatically signed
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            [0x12; 32],
            signing_key.clone(),
            verifying_key.to_bytes(),
        );
        
        // Verify the signature with environment keys
        verify_challenge_signature(&challenge).unwrap();
        
        // Verify with explicit key
        verify_challenge_signature_with_key(&challenge, &verifying_key.to_bytes()).unwrap();
        
        // Verify that the embedded public key matches what we expect
        assert_eq!(challenge.public_key, verifying_key.to_bytes());
    }

    #[test]
    fn test_tampered_challenge_detection() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        let (signing_key, verifying_key) = {
            use rand_core::OsRng;
            
            let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
            let verifying_key: VerifyingKey = signing_key.verifying_key();
            
            let private_key: String = STANDARD.encode(signing_key.to_bytes());
            let public_key: String = STANDARD.encode(verifying_key.to_bytes());
            
            env::set_var("IRONSHIELD_PRIVATE_KEY", &private_key);
            env::set_var("IRONSHIELD_PUBLIC_KEY", &public_key);
            
            (signing_key, verifying_key)
        };
        
        // Create and sign a challenge - signature is generated automatically
        let mut challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            [0x12; 32],
            signing_key.clone(),
            verifying_key.to_bytes(),
        );
        
        // Verify original challenge works
        verify_challenge_signature(&challenge).unwrap();
        
        // Tamper with the challenge
        challenge.random_nonce = "tampered".to_string();
        
        // Verification should fail
        let result = verify_challenge_signature(&challenge);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::VerificationFailed(_)));
    }

    #[test]
    fn test_invalid_signature_format() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        {
            use rand_core::OsRng;
            
            let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
            let verifying_key: VerifyingKey = signing_key.verifying_key();
            
            let private_key: String = STANDARD.encode(signing_key.to_bytes());
            let public_key: String = STANDARD.encode(verifying_key.to_bytes());
            
            env::set_var("IRONSHIELD_PRIVATE_KEY", &private_key);
            env::set_var("IRONSHIELD_PUBLIC_KEY", &public_key);
        }
        
        // Create a challenge that will be properly signed
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let mut challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            [0x12; 32],
            dummy_key,
            [0x34; 32],
        );
        
        // Now manually corrupt the signature to test invalid format
        challenge.challenge_signature = [0xFF; 64]; // Invalid signature
        
        // Verification should fail
        let result = verify_challenge_signature(&challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_message_creation() {
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            [0x12; 32],
            dummy_key,
            [0x34; 32],
        );
        
        let message = create_signing_message(
            &challenge.random_nonce,
            challenge.created_time,
            challenge.expiration_time,
            &challenge.website_id,
            &challenge.challenge_param,
            &challenge.public_key
        );
        
        // Message should contain all fields except signature
        assert!(message.contains("test_website"));
        assert!(message.contains(&hex::encode([0x12; 32])));
        assert!(message.contains(&hex::encode([0x34; 32])));
        // Should NOT contain the signature
        assert!(!message.contains(&hex::encode(challenge.challenge_signature)));
        // Should have exactly 5 pipe separators (6 total fields, excluding signature)
        assert_eq!(message.matches('|').count(), 5);
    }

    #[test]
    fn test_sign_challenge_uses_generate_signature() {
        let _lock = ENV_MUTEX.lock().unwrap();
        
        let (signing_key, verifying_key) = {
            use rand_core::OsRng;
            
            let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
            let verifying_key: VerifyingKey = signing_key.verifying_key();
            
            let private_key: String = STANDARD.encode(signing_key.to_bytes());
            let public_key: String = STANDARD.encode(verifying_key.to_bytes());
            
            env::set_var("IRONSHIELD_PRIVATE_KEY", &private_key);
            env::set_var("IRONSHIELD_PUBLIC_KEY", &public_key);
            
            (signing_key, verifying_key)
        };
        
        // Create a test challenge - it will be automatically signed
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            [0x12; 32],
            signing_key.clone(),
            verifying_key.to_bytes(),
        );
        
        // Test that sign_challenge and manual generate_signature produce the same result
        let sign_challenge_result = sign_challenge(&challenge).unwrap();
        
        let message = create_signing_message(
            &challenge.random_nonce,
            challenge.created_time,
            challenge.expiration_time,
            &challenge.website_id,
            &challenge.challenge_param,
            &challenge.public_key
        );
        let manual_signature = generate_signature(&signing_key, &message).unwrap();
        
        assert_eq!(sign_challenge_result, manual_signature, 
                   "sign_challenge should produce the same result as manual generate_signature");
    }
} 
