//! # Cryptographic operations for IronShield challenges
//! 
//! This module provides Ed25519 signature generation and verification for IronShield challenges,
//! including key management from environment variables and challenge signing/verification.
//!
//! ## Features
//!
//! ### Key Management
//! - `load_private_key_from_env()` - Load Ed25519 private key from environment
//! - `load_public_key_from_env()` - Load Ed25519 public key from environment  
//! - `generate_test_keypair()` - Generate keypairs for testing
//!
//! ### Challenge Signing
//! - `sign_challenge()` - Sign challenges with environment private key
//! - `create_signed_challenge()` - Create and sign challenges in one step
//!
//! ### Challenge Verification
//! - `verify_challenge_signature()` - Verify using environment public key
//! - `verify_challenge_signature_with_key()` - Verify using provided key
//! - `validate_challenge()` - Comprehensive validation (signature + expiration)
//!
//! ## Security Design
//!
//! ### Signature Coverage
//! Signatures cover all challenge fields except the signature itself:
//! - `random_nonce` 
//! - `created_time`
//! - `expiration_time`
//! - `website_id`
//! - `challenge_param` (hex-encoded)
//! - `public_key` (hex-encoded)
//!
//! This prevents tampering with any challenge parameters while allowing verification.
//!
//! ### Environment Variables
//! - `IRONSHIELD_PRIVATE_KEY` - Base64-encoded Ed25519 private key (32 bytes)
//! - `IRONSHIELD_PUBLIC_KEY` - Base64-encoded Ed25519 public key (32 bytes)
//!
//! ## Usage Examples
//!
//! ### Server-side: Creating signed challenges
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use ironshield_types::*;
//! 
//! // Set environment variables with your keypair
//! std::env::set_var("IRONSHIELD_PRIVATE_KEY", "your_base64_private_key");
//! std::env::set_var("IRONSHIELD_PUBLIC_KEY", "your_base64_public_key");
//!
//! // Create a signed challenge
//! let challenge = create_signed_challenge(
//!     "random_nonce_123".to_string(),
//!     chrono::Utc::now().timestamp_millis(),
//!     "example.com".to_string(),
//!     IronShieldChallenge::difficulty_to_challenge_param(50000),
//! )?;
//!
//! // Send as base64url header
//! let header_value = challenge.to_base64url_header();
//! # Ok(())
//! # }
//! ```
//!
//! ### Client-side: Verifying challenges  
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use ironshield_types::*;
//!
//! # let header_value = "example_base64url_data";
//! // Receive challenge from header
//! let challenge = IronShieldChallenge::from_base64url_header(&header_value)?;
//!
//! // Verify signature using embedded public key
//! verify_challenge_signature_with_key(&challenge, &challenge.public_key)?;
//!
//! // Comprehensive validation
//! validate_challenge(&challenge)?;
//! # Ok(())
//! # }
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
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::MissingEnvironmentVariable(var) => write!(f, "Missing environment variable: {}", var),
            CryptoError::InvalidKeyFormat(msg) => write!(f, "Invalid key format: {}", msg),
            CryptoError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            CryptoError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            CryptoError::Base64DecodingFailed(msg) => write!(f, "Base64 decoding failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Loads the private key from the IRONSHIELD_PRIVATE_KEY environment variable
/// 
/// The environment variable should contain a base64-encoded Ed25519 private key (32 bytes).
/// 
/// # Returns
/// * `Result<SigningKey, CryptoError>` - The Ed25519 signing key or an error
/// 
/// # Environment Variables
/// * `IRONSHIELD_PRIVATE_KEY` - Base64-encoded Ed25519 private key
pub fn load_private_key_from_env() -> Result<SigningKey, CryptoError> {
    let key_str: String = env::var("IRONSHIELD_PRIVATE_KEY")
        .map_err(|_| CryptoError::MissingEnvironmentVariable("IRONSHIELD_PRIVATE_KEY".to_string()))?;
    
    // Decode from base64
    let key_bytes: Vec<u8> = STANDARD.decode(key_str.trim())
        .map_err(|e| CryptoError::Base64DecodingFailed(format!("Private key: {}", e)))?;
    
    // Verify length
    if key_bytes.len() != SECRET_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyFormat(
            format!("Private key must be {} bytes, got {}", SECRET_KEY_LENGTH, key_bytes.len())
        ));
    }
    
    // Create signing key
    let key_array: [u8; SECRET_KEY_LENGTH] = key_bytes.try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Failed to convert private key bytes".to_string()))?;
    
    let signing_key: SigningKey = SigningKey::from_bytes(&key_array);
    Ok(signing_key)
}

/// Loads the public key from the IRONSHIELD_PUBLIC_KEY environment variable
/// 
/// The environment variable should contain a base64-encoded Ed25519 public key (32 bytes).
/// 
/// # Returns
/// * `Result<VerifyingKey, CryptoError>` - The Ed25519 verifying key or an error
/// 
/// # Environment Variables
/// * `IRONSHIELD_PUBLIC_KEY` - Base64-encoded Ed25519 public key
pub fn load_public_key_from_env() -> Result<VerifyingKey, CryptoError> {
    let key_str: String = env::var("IRONSHIELD_PUBLIC_KEY")
        .map_err(|_| CryptoError::MissingEnvironmentVariable("IRONSHIELD_PUBLIC_KEY".to_string()))?;
    
    // Decode from base64
    let key_bytes: Vec<u8> = STANDARD.decode(key_str.trim())
        .map_err(|e| CryptoError::Base64DecodingFailed(format!("Public key: {}", e)))?;
    
    // Verify length
    if key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyFormat(
            format!("Public key must be {} bytes, got {}", PUBLIC_KEY_LENGTH, key_bytes.len())
        ));
    }
    
    // Create verifying key
    let key_array: [u8; PUBLIC_KEY_LENGTH] = key_bytes.try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Failed to convert public key bytes".to_string()))?;
    
    let verifying_key: VerifyingKey = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid public key: {}", e)))?;
    
    Ok(verifying_key)
}

/// Creates a message to be signed from challenge data (excluding the signature field)
/// 
/// This function creates a canonical representation of the challenge data for signing.
/// It uses the same format as `concat_struct()` but excludes the signature field.
/// 
/// # Arguments
/// * `challenge` - The challenge to create a signing message for
/// 
/// # Returns
/// * `String` - Canonical string representation for signing
fn create_signing_message(challenge: &IronShieldChallenge) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        challenge.random_nonce,
        challenge.created_time,
        challenge.expiration_time,
        challenge.website_id,
        hex::encode(challenge.challenge_param),
        hex::encode(challenge.public_key)
    )
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
/// use ironshield_types::{IronShieldChallenge, sign_challenge};
/// 
/// let mut challenge = IronShieldChallenge::new(
///     "deadbeef".to_string(),
///     1000000,
///     "test_website".to_string(),
///     [0x12; 32],
///     [0x34; 32],
///     [0x00; 64], // Empty signature initially
/// );
/// 
/// // Sign the challenge (requires IRONSHIELD_PRIVATE_KEY environment variable)
/// let signature = sign_challenge(&challenge).unwrap();
/// challenge.challenge_signature = signature;
/// ```
pub fn sign_challenge(challenge: &IronShieldChallenge) -> Result<[u8; 64], CryptoError> {
    let signing_key: SigningKey = load_private_key_from_env()?;
    
    let message: String = create_signing_message(challenge);
    let signature: Signature = signing_key.sign(message.as_bytes());
    
    Ok(signature.to_bytes())
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
/// use ironshield_types::{IronShieldChallenge, verify_challenge_signature};
/// 
/// let challenge = IronShieldChallenge::new(
///     "deadbeef".to_string(),
///     1000000,
///     "test_website".to_string(),
///     [0x12; 32],
///     [0x34; 32],
///     [0u8; 64], // Valid signature
/// );
/// 
/// // Verify the challenge (requires IRONSHIELD_PUBLIC_KEY environment variable)
/// verify_challenge_signature(&challenge).unwrap();
/// ```
pub fn verify_challenge_signature(challenge: &IronShieldChallenge) -> Result<(), CryptoError> {
    let verifying_key: VerifyingKey = load_public_key_from_env()?;
    
    let message: String = create_signing_message(challenge);
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
    
    let message: String = create_signing_message(challenge);
    let signature: Signature = Signature::from_slice(&challenge.challenge_signature)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid signature format: {}", e)))?;
    
    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|e| CryptoError::VerificationFailed(format!("Signature verification failed: {}", e)))?;
    
    Ok(())
}

/// Generates a new Ed25519 keypair for testing purposes
/// 
/// This function generates a fresh keypair and returns the keys in base64 format
/// suitable for use as environment variables.
/// 
/// # Returns
/// * `(String, String)` - (base64_private_key, base64_public_key)
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

/// Creates a signed challenge using environment keys
/// 
/// This is a convenience function that creates a challenge with proper signature.
/// It automatically loads the private key and sets the public key in the challenge.
/// 
/// # Arguments
/// * `random_nonce` - Random nonce string
/// * `created_time` - Challenge creation timestamp
/// * `website_id` - Website identifier
/// * `challenge_param` - Challenge parameter for PoW difficulty
/// 
/// # Returns
/// * `Result<IronShieldChallenge, CryptoError>` - Signed challenge or error
/// 
/// # Example
/// ```no_run
/// use ironshield_types::create_signed_challenge;
/// 
/// let challenge = create_signed_challenge(
///     "deadbeef123".to_string(),
///     1700000000000,
///     "example.com".to_string(),
///     [0x12; 32],
/// ).unwrap();
/// ```
pub fn create_signed_challenge(
    random_nonce: String,
    created_time: i64,
    website_id: String,
    challenge_param: [u8; 32],
) -> Result<IronShieldChallenge, CryptoError> {
    // Load the public key from environment
    let verifying_key: VerifyingKey = load_public_key_from_env()?;
    
    // Create challenge with empty signature initially
    let mut challenge = IronShieldChallenge::new(
        random_nonce,
        created_time,
        website_id,
        challenge_param,
        verifying_key.to_bytes(),
        [0u8; 64],
    );
    
    // Sign the challenge
    let signature: [u8; 64] = sign_challenge(&challenge)?;
    challenge.challenge_signature = signature;
    
    Ok(challenge)
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
    
    // Basic format validation
    if challenge.random_nonce.is_empty() {
        return Err(CryptoError::VerificationFailed("Empty random_nonce".to_string()));
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
            "test_nonce_123".to_string(),
            1700000000000,
            "example.com".to_string(),
            [0xAB; 32],
            verifying_key.to_bytes(),
            [0u8; 64], // Empty signature initially
        );
        
        // Create the signing message manually
        let signing_message = create_signing_message(&challenge);
        println!("Signing message: {}", signing_message);
        
        // Sign the message directly with the signing key
        let signature: Signature = signing_key.sign(signing_message.as_bytes());
        let signature_bytes: [u8; 64] = signature.to_bytes();
        
        // Create the signed challenge
        let mut signed_challenge = challenge.clone();
        signed_challenge.challenge_signature = signature_bytes;
        
        // Verify manually with the verifying key
        let verification_message = create_signing_message(&signed_challenge);
        assert_eq!(signing_message, verification_message, "Signing message should be consistent");
        
        let signature_from_bytes = Signature::from_slice(&signature_bytes)
            .expect("Should be able to recreate signature from bytes");
        
        let verification_result = verifying_key.verify(verification_message.as_bytes(), &signature_from_bytes);
        assert!(verification_result.is_ok(), "Manual verification should succeed");
        
        // Now test our helper function
        let verify_result = verify_challenge_signature_with_key(&signed_challenge, &verifying_key.to_bytes());
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
        
        // Create a test challenge with the public key embedded
        let mut challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x12; 32],
            verifying_key.to_bytes(),
            [0x00; 64], // Empty signature initially
        );
        
        // Sign the challenge
        let signature = sign_challenge(&challenge).unwrap();
        challenge.challenge_signature = signature;
        
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
        
        // Create and sign a challenge
        let mut challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x12; 32],
            verifying_key.to_bytes(),
            [0x00; 64],
        );
        
        let signature = sign_challenge(&challenge).unwrap();
        challenge.challenge_signature = signature;
        
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
    fn test_create_signed_challenge() {
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
        
        // Create a signed challenge
        let challenge = create_signed_challenge(
            "test_nonce".to_string(),
            1700000000000,
            "example.com".to_string(),
            [0xAB; 32],
        ).unwrap();
        
        // Verify the challenge is properly signed
        verify_challenge_signature(&challenge).unwrap();
        
        // Check that fields are set correctly
        assert_eq!(challenge.random_nonce, "test_nonce");
        assert_eq!(challenge.created_time, 1700000000000);
        assert_eq!(challenge.website_id, "example.com");
        assert_eq!(challenge.challenge_param, [0xAB; 32]);
        assert_ne!(challenge.challenge_signature, [0u8; 64]); // Should not be empty
    }

    #[test]
    fn test_validate_challenge() {
        let (_, verifying_key) = setup_isolated_test_keys();
        
        // Create a valid challenge
        let challenge = create_signed_challenge(
            "valid_nonce".to_string(),
            chrono::Utc::now().timestamp_millis(),
            "example.com".to_string(),
            [0xCD; 32],
        ).unwrap();
        
        // Should validate successfully
        validate_challenge(&challenge).unwrap();
        
        // Test expired challenge
        let expired_challenge = IronShieldChallenge::new(
            "expired_nonce".to_string(),
            1000000000, // Very old timestamp
            "example.com".to_string(),
            [0xEF; 32],
            verifying_key.to_bytes(),
            [0u8; 64],
        );
        
        let result = validate_challenge(&expired_challenge);
        assert!(result.is_err());
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
        
        // Create a challenge with invalid signature
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x12; 32],
            [0x34; 32],
            [0xFF; 64], // Invalid signature
        );
        
        // Verification should fail
        let result = verify_challenge_signature(&challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_message_creation() {
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x12; 32],
            [0x34; 32],
            [0x56; 64],
        );
        
        let message = create_signing_message(&challenge);
        
        // Message should contain all fields except signature
        assert!(message.contains("deadbeef"));
        assert!(message.contains("1000000"));
        assert!(message.contains("test_website"));
        assert!(message.contains(&hex::encode([0x12; 32])));
        assert!(message.contains(&hex::encode([0x34; 32])));
        // Should NOT contain the signature
        assert!(!message.contains(&hex::encode([0x56; 64])));
        // Should have exactly 5 pipe separators (6 total fields, excluding signature)
        assert_eq!(message.matches('|').count(), 5);
    }
} 
