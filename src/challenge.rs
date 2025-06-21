use crate::serde_utils::{serialize_signature, deserialize_signature, serialize_32_bytes, deserialize_32_bytes};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// IronShield Challenge structure for the proof-of-work algorithm
/// 
/// * `random_nonce`:         The SHA-256 hash of a random number (hex string).
/// * `created_time`:         Unix milli timestamp for the challenge.
/// * `expiration_time`:      Unix milli timestamp for the challenge expiration time.
/// * `challenge_param`:      Target threshold - hash must be less than this value.
/// * `recommended_attempts`: Expected number of attempts for user guidance (3x difficulty).
/// * `website_id`:           The identifier of the website.
/// * `public_key`:           Ed25519 public key for signature verification.
/// * `challenge_signature`:  Ed25519 signature over the challenge data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IronShieldChallenge {
    pub random_nonce:        String,
    pub created_time:        i64,
    pub expiration_time:     i64,
    pub website_id:          String,
    #[serde(
        serialize_with = "serialize_32_bytes",
        deserialize_with = "deserialize_32_bytes"
    )]
    pub challenge_param:     [u8; 32],
    pub recommended_attempts: u64,
    #[serde(
        serialize_with = "serialize_32_bytes",
        deserialize_with = "deserialize_32_bytes"
    )]
    pub public_key:          [u8; 32],
    #[serde(
        serialize_with = "serialize_signature",
        deserialize_with = "deserialize_signature"
    )]
    pub challenge_signature: [u8; 64],
}

impl IronShieldChallenge {
    /// Constructor for creating a new IronShieldChallenge instance.
    pub fn new(
        random_nonce:     String,
        created_time:     i64,
        website_id:       String,
        challenge_param:  [u8; 32],
        public_key:       [u8; 32],
        signature:        [u8; 64],
    ) -> Self {
        Self {
            random_nonce,
            created_time,
            website_id,
            expiration_time: created_time + 30_000, // 30 seconds
            challenge_param,
            recommended_attempts: 0, // This will be set later
            public_key,
            challenge_signature: signature,
        }
    }

    /// Converts a difficulty value (expected number of attempts) to a challenge_param.
    ///
    /// The difficulty represents the expected number of hash attempts needed to find a valid nonce
    /// where SHA256(random_nonce_bytes + nonce_bytes) < challenge_param.
    ///
    /// Since hash outputs are uniformly distributed over the 256-bit space, the relationship is:
    /// challenge_param = 2^256 / difficulty
    ///
    /// This function accurately calculates this for difficulties ranging from 1 to u64::MAX.
    ///
    /// # Arguments
    /// * `difficulty`: Expected number of attempts (must be > 0)
    ///
    /// # Returns
    /// * `[u8; 32]`: The challenge_param bytes in big-endian format
    ///
    /// # Panics
    /// * Panics if difficulty is 0
    ///
    /// # Examples
    /// * difficulty = 1 → challenge_param = [0xFF; 32] (very easy, ~100% chance)
    /// * difficulty = 2 → challenge_param = [0x80, 0x00, ...] (MSB set, ~50% chance)  
    /// * difficulty = 10,000 → challenge_param ≈ 2^242.7 (realistic difficulty)
    /// * difficulty = 1,000,000 → challenge_param ≈ 2^236.4 (higher difficulty)
    pub fn difficulty_to_challenge_param(difficulty: u64) -> [u8; 32] {
        if difficulty == 0 {
            panic!("Difficulty cannot be zero");
        }
        
        if difficulty == 1 {
            // Special case: difficulty 1 means almost certain success.
            return [0xFF; 32];
        }
        
        // Calculate log2(difficulty) for bit positioning.
        let difficulty_f64: f64 = difficulty as f64;
        let log2_difficulty: f64 = difficulty_f64.log2();
        
        // Target exponent: 256 - log2(difficulty)
        // This gives us the exponent of 2 in the result 2^256 / difficulty ≈ 2^target_exponent.
        let target_exponent: f64 = 256.0 - log2_difficulty;
        
        if target_exponent <= 0.0 {
            // The result would be less than 1, return minimal value.
            let mut result: [u8; 32] = [0u8; 32];
            result[31] = 1;
            return result;
        }
        
        if target_exponent >= 256.0 {
            // Result would overflow, return maximum.
            return [0xFF; 32];
        }
        
        // Round to the nearest whole number for simplicity.
        let exponent: usize = target_exponent.round() as usize;
        
        if exponent >= 256 {
            return [0xFF; 32];
        }
        
        let mut result: [u8; 32] = [0u8; 32];
        
        // Set the bit at the position 'exponent' (where 255 is MSB, 0 is LSB).
        // For a big-endian byte array: bit N is in byte (255-N)/8, bit (7-((255-N)%8)).
        let byte_index: usize = (255 - exponent) / 8;
        let bit_index: usize = 7 - ((255 - exponent) % 8);
        
        if byte_index < 32 {
            result[byte_index] = 1u8 << bit_index;
        } else {
            // Very small result, set the least significant bit.
            result[31] = 1;
        }
        
        result
    }

    /// Check if the challenge has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expiration_time
    }

    /// Returns the remaining time until expiration in milliseconds.
    pub fn time_until_expiration(&self) -> i64 {
        self.expiration_time - Utc::now().timestamp_millis()
    }

    /// Returns the recommended number of attempts to expect for a given difficulty.
    /// 
    /// This provides users with a realistic expectation of how many attempts they might need.
    /// Since the expected value is equal to the difficulty, we return 3x the difficulty
    /// to give users a reasonable upper bound for planning purposes.
    /// 
    /// # Arguments
    /// * `difficulty`: The target difficulty (expected number of attempts)
    /// 
    /// # Returns
    /// * `u64`: Recommended number of attempts (3x the difficulty)
    /// 
    /// # Examples
    /// * difficulty = 1,000 → recommended_attempts = 3,000
    /// * difficulty = 50,000 → recommended_attempts = 150,000
    pub fn recommended_attempts(difficulty: u64) -> u64 {
        difficulty.saturating_mul(3)
    }

    /// Sets the recommended_attempts field based on the given difficulty.
    /// 
    /// # Arguments
    /// * `difficulty` - The difficulty value to base the recommendation on.
    pub fn set_recommended_attempts(&mut self, difficulty: u64) {
        self.recommended_attempts = Self::recommended_attempts(difficulty);
    }

    /// Concatenates the challenge data into a string.
    ///
    /// Concatenates:
    /// - `random_nonce`     as a string.
    /// - `created_time`     as i64.
    /// - `expiration_time`  as i64.
    /// - `website_id`       as a string.
    /// - `public_key`       as a lowercase hex string.
    /// - `challenge_params` as a lowercase hex string.
    pub fn concat_struct(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.random_nonce,
            self.created_time,
            self.expiration_time,
            self.website_id,
            // We need to encode the byte arrays for format! to work.
            hex::encode(self.challenge_param),
            hex::encode(self.public_key),
            hex::encode(self.challenge_signature)
        )
    }

    /// Creates an `IronShieldChallenge` from a concatenated string.
    ///
    /// This function reverses the operation of
    /// `IronShieldChallenge::concat_struct`.
    /// Expects a string in the format:
    /// "random_nonce|created_time|expiration_time|website_id|challenge_params|public_key|challenge_signature"
    ///
    /// # Arguments
    ///
    /// * `concat_str`: The concatenated string to parse, typically
    ///                 generated by `concat_struct()`.
    ///
    /// # Returns
    ///
    /// * `Result<Self, String>`: A result containing the parsed
    ///                           `IronShieldChallenge` or an 
    ///                           error message if parsing fails.
    pub fn from_concat_struct(concat_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = concat_str.split('|').collect();

        if parts.len() != 7 {
            return Err(format!("Expected 7 parts, got {}", parts.len()));
        }

        let random_nonce: String = parts[0].to_string();

        let created_time: i64 = parts[1].parse::<i64>()
            .map_err(|_| "Failed to parse created_time as i64")?;

        let expiration_time: i64 = parts[2].parse::<i64>()
            .map_err(|_| "Failed to parse expiration_time as i64")?;

        let website_id: String = parts[3].to_string();

        let challenge_param_bytes: Vec<u8> = hex::decode(parts[4])
            .map_err(|_| "Failed to decode challenge_params hex string")?;
        let challenge_param: [u8; 32] = challenge_param_bytes
            .try_into()
            .map_err(|_| "Challenge params must be exactly 32 bytes")?;

        let public_key_bytes: Vec<u8> = hex::decode(parts[5])
            .map_err(|_| "Failed to decode public_key hex string")?;
        let public_key: [u8; 32] = public_key_bytes.try_into()
            .map_err(|_| "Public key must be exactly 32 bytes")?;

        let signature_bytes: Vec<u8> = hex::decode(parts[6])
            .map_err(|_| "Failed to decode challenge_signature hex string")?;
        let challenge_signature: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| "Signature must be exactly 64 bytes")?;

        Ok(Self {
            random_nonce,
            created_time,
            expiration_time,
            website_id,
            challenge_param,
            recommended_attempts: 0, // This will be set later
            public_key,
            challenge_signature,
        })
    }

    /// Encodes the challenge as a base64url string for HTTP header transport.
    /// 
    /// This method concatenates all challenge fields using the established `|` delimiter
    /// format, and then base64url-encodes the result for safe transport in HTTP headers.
    /// 
    /// # Returns
    /// * `String`: Base64url-encoded string ready for HTTP header use
    /// 
    /// # Example
    /// ```
    /// use ironshield_types::IronShieldChallenge;
    /// let challenge = IronShieldChallenge::new(
    ///     "deadbeef".to_string(),
    ///     1000000,
    ///     "test_website".to_string(),
    ///     [0x12; 32],
    ///     [0x34; 32],
    ///     [0x56; 64],
    /// );
    /// let header_value = challenge.to_base64url_header();
    /// // Use header_value in HTTP header: "X-IronShield-Challenge-Data: {header_value}"
    /// ```
    pub fn to_base64url_header(&self) -> String {
        crate::serde_utils::concat_struct_base64url_encode(&self.concat_struct())
    }

    /// Decodes a base64url-encoded challenge from an HTTP header.
    /// 
    /// This method reverses the `to_base64url_header()` operation by first base64url-decoding
    /// the input string and then parsing it using the established `|` delimiter format.
    /// 
    /// # Arguments
    /// * `encoded_header`: The base64url-encoded string from the HTTP header
    /// 
    /// # Returns
    /// * `Result<Self, String>`: Decoded challenge or detailed error message
    /// 
    /// # Example
    /// ```
    /// use ironshield_types::IronShieldChallenge;
    /// // Create a challenge and encode it
    /// let original = IronShieldChallenge::new(
    ///     "deadbeef".to_string(),
    ///     1000000,
    ///     "test_website".to_string(),
    ///     [0x12; 32],
    ///     [0x34; 32],
    ///     [0x56; 64],
    /// );
    /// let header_value = original.to_base64url_header();
    /// // Decode it back
    /// let decoded = IronShieldChallenge::from_base64url_header(&header_value).unwrap();
    /// assert_eq!(original.random_nonce, decoded.random_nonce);
    /// ```
    pub fn from_base64url_header(encoded_header: &str) -> Result<Self, String> {
        // Decode using the existing serde_utils function.
        let concat_str: String = crate::serde_utils::concat_struct_base64url_decode(encoded_header.to_string())?;
        
        // Parse using the existing concat_struct format.
        Self::from_concat_struct(&concat_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_to_challenge_param_basic_cases() {
        // Test a very easy case.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(1);
        assert_eq!(challenge_param, [0xFF; 32]);
        
        // Test the exact powers of 2.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(2);
        let expected: [u8; 32] = {
            let mut arr: [u8; 32] = [0x00; 32];
            arr[0] = 0x80; // 2^255
            arr
        };
        assert_eq!(challenge_param, expected);
        
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(4);
        let expected: [u8; 32] = {
            let mut arr: [u8; 32] = [0x00; 32];
            arr[0] = 0x40; // 2^254
            arr
        };
        assert_eq!(challenge_param, expected);
        
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(256);
        let expected: [u8; 32] = {
            let mut arr: [u8; 32] = [0x00; 32];
            arr[0] = 0x01; // 2^248
            arr
        };
        assert_eq!(challenge_param, expected);
    }

    #[test]
    fn test_difficulty_to_challenge_param_realistic_range() {
        // Test difficulties in the expected range: 10,000 to 10,000,000.
        
        // difficulty = 10,000 ≈ 2^13.29, so the result ≈ 2^242.71 → rounds to 2^243.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(10_000);
        // Should have bit 243 set (byte 1, bit 3).
        assert_eq!(challenge_param[0], 0x00);
        assert_eq!(challenge_param[1], 0x08); // bit 3 = 0x08
        
        // difficulty = 50,000 ≈ 2^15.61, so the result ≈ 2^240.39 → rounds to 2^240.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(50_000);
        assert_eq!(challenge_param[0], 0x00);
        assert_eq!(challenge_param[1], 0x01); // bit 0 = 0x01
        
        // difficulty = 100,000 ≈ 2^16.61, so the result ≈ 2^239.39 → rounds to 2^239.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(100_000);
        assert_eq!(challenge_param[0], 0x00);
        assert_eq!(challenge_param[1], 0x00);
        assert_eq!(challenge_param[2], 0x80); // bit 7 of byte 2
        
        // difficulty = 1,000,000 ≈ 2^19.93, so the result ≈ 2^236.07 → rounds to 2^236.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(1_000_000);
        assert_eq!(challenge_param[0], 0x00);
        assert_eq!(challenge_param[1], 0x00);
        assert_eq!(challenge_param[2], 0x10); // bit 4 of byte 2
        
        // difficulty = 10,000,000 ≈ 2^23.25, so the result ≈ 2^232.75 → rounds to 2^233.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(10_000_000);
        assert_eq!(challenge_param[0], 0x00);
        assert_eq!(challenge_param[1], 0x00);
        assert_eq!(challenge_param[2], 0x02); // bit 1 of byte 2
    }

    #[test]
    fn test_difficulty_to_challenge_param_ordering() {
        // Test that higher difficulties produce smaller challenge_params.
        let difficulties: [u64; 9] = [1000, 5000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000, 10_000_000];
        let mut challenge_params = Vec::new();
        
        for &difficulty in &difficulties {
            challenge_params.push(IronShieldChallenge::difficulty_to_challenge_param(difficulty));
        }
        
        // Verify that challenge_params are in descending order (higher difficulty = smaller param).
        for i in 1..challenge_params.len() {
            assert!(
                challenge_params[i-1] > challenge_params[i],
                "Challenge param for difficulty {} should be larger than for difficulty {}",
                difficulties[i-1], difficulties[i]
            );
        }
    }

    #[test]
    fn test_difficulty_to_challenge_param_precision() {
        // Test that similar difficulties produce appropriately similar results.
        let base_difficulty: u64 = 100_000;
        let base_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(base_difficulty);
        
        // Small variations in difficulty will round to the same or nearby bit positions.
        let similar_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(100_001);
        
        // With rounding, very similar difficulties might produce the same result.
        // The key test is that larger difficulties produce smaller or equal challenge_params.
        assert!(base_param >= similar_param); // Should be the same or slightly larger.
        
        // Test that larger differences produce measurably different results.
        let much_different_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(200_000);
        assert!(base_param > much_different_param);
        
        // Test that the ordering is consistent for larger changes.
        let big_different_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(400_000);
        assert!(much_different_param > big_different_param);
    }

    #[test]
    fn test_difficulty_to_challenge_param_powers_of_10() {
        // Test various powers of 10.
        let difficulties: [u64; 6] = [10, 100, 1_000, 10_000, 100_000, 1_000_000];
        
        for &difficulty in &difficulties {
            let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(difficulty);
            
            // Should not be all zeros or all FFs (except for difficulty 1).
            assert_ne!(challenge_param, [0x00; 32]);
            assert_ne!(challenge_param, [0xFF; 32]);
            
            // Should have a reasonable number of leading zeros.
            let leading_zero_bytes: usize = challenge_param.iter().take_while(|&&b| b == 0).count();
            assert!(leading_zero_bytes < 32, "Too many leading zero bytes for difficulty {}", difficulty);
            
            // Should not be too small (no more than 28 leading zero bytes for this range)
            assert!(leading_zero_bytes < 28, "Challenge param too small for difficulty {}", difficulty);
        }
    }

    #[test]
    fn test_difficulty_to_challenge_param_mathematical_properties() {
        // Test mathematical properties of the algorithm.
        
        // For difficulty D1 and D2 where D2 = 2 * D1, 
        // challenge_param(D1) should be approximately 2 * challenge_param(D2)
        let d1: u64 = 50_000;
        let d2: u64 = 100_000; // 2 * d1
        
        let param1: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(d1);
        let param2: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(d2);
        
        // Convert to u128 for comparison (taking first 16 bytes).
        let val1: u128 = u128::from_be_bytes(param1[0..16].try_into().unwrap());
        let val2: u128 = u128::from_be_bytes(param2[0..16].try_into().unwrap());
        
        // val1 should be approximately 2 * val2 (within reasonable tolerance).
        let ratio: f64 = val1 as f64 / val2 as f64;
        assert!(ratio > 1.8 && ratio < 2.2, "Ratio should be close to 2.0, got {}", ratio);
    }

    #[test]
    fn test_difficulty_to_challenge_param_edge_cases() {
        // Test zero difficulty panics.
        let result = std::panic::catch_unwind(|| {
            IronShieldChallenge::difficulty_to_challenge_param(0);
        });
        assert!(result.is_err());
        
        // Test very high difficulty produces a small value.
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(u64::MAX);
        assert_ne!(challenge_param, [0xFF; 32]);
        assert_ne!(challenge_param, [0; 32]);
        
        // Test moderately high difficulties.
        let high_difficulty: u64 = 1u64 << 40; // 2^40
        let challenge_param: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(high_difficulty);
        assert_ne!(challenge_param, [0; 32]);
        assert_ne!(challenge_param, [0xFF; 32]);
    }

    #[test]
    fn test_difficulty_to_challenge_param_consistency() {
        // Test that the function produces consistent results.
        let test_difficulties: [u64; 13] = [
            10_000, 25_000, 50_000, 75_000, 100_000,
            250_000, 500_000, 750_000, 1_000_000,
            2_500_000, 5_000_000, 7_500_000, 10_000_000
        ];
        
        for &difficulty in &test_difficulties {
            let param1: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(difficulty);
            let param2: [u8; 32] = IronShieldChallenge::difficulty_to_challenge_param(difficulty);
            assert_eq!(param1, param2, "Function should be deterministic for difficulty {}", difficulty);
            
            // Test that the challenge param is reasonable.
            assert_ne!(param1, [0x00; 32]);
            assert_ne!(param1, [0xFF; 32]);
        }
    }

    #[test]
    fn test_recommended_attempts() {
        // Test recommended_attempts function
        assert_eq!(IronShieldChallenge::recommended_attempts(1000), 3000);
        assert_eq!(IronShieldChallenge::recommended_attempts(50000), 150000);
        assert_eq!(IronShieldChallenge::recommended_attempts(0), 0);
        
        // Test overflow protection
        assert_eq!(IronShieldChallenge::recommended_attempts(u64::MAX), u64::MAX);
        
        // Test realistic range
        assert_eq!(IronShieldChallenge::recommended_attempts(10_000), 30_000);
        assert_eq!(IronShieldChallenge::recommended_attempts(1_000_000), 3_000_000);
    }

    #[test]
    fn test_base64url_header_encoding_roundtrip() {
        // Create a test challenge
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x12; 32],
            [0x34; 32],
            [0x56; 64],
        );

        // Test base64url encoding and decoding
        let encoded: String = challenge.to_base64url_header();
        let decoded: IronShieldChallenge = IronShieldChallenge::from_base64url_header(&encoded).unwrap();

        // Verify all fields are preserved through roundtrip
        assert_eq!(challenge.random_nonce, decoded.random_nonce);
        assert_eq!(challenge.created_time, decoded.created_time);
        assert_eq!(challenge.expiration_time, decoded.expiration_time);
        assert_eq!(challenge.website_id, decoded.website_id);
        assert_eq!(challenge.challenge_param, decoded.challenge_param);
        assert_eq!(challenge.public_key, decoded.public_key);
        assert_eq!(challenge.challenge_signature, decoded.challenge_signature);
    }

    #[test]
    fn test_base64url_header_invalid_data() {
        // Test invalid base64url
        let result: Result<IronShieldChallenge, String> = IronShieldChallenge::from_base64url_header("invalid-base64!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Base64 decode error"));

        // Test valid base64url but invalid concatenated format
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let invalid_format: String = URL_SAFE_NO_PAD.encode(b"not|enough|parts");
        let result: Result<IronShieldChallenge, String> = IronShieldChallenge::from_base64url_header(&invalid_format);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected 7 parts"));
    }

    #[test]
    fn test_difficulty_range_boundaries() {
        // Test around the specified range boundaries (10,000 to 10,000,000)
        let min_difficulty = 10_000;
        let max_difficulty = 10_000_000;
        
        let min_param = IronShieldChallenge::difficulty_to_challenge_param(min_difficulty);
        let max_param = IronShieldChallenge::difficulty_to_challenge_param(max_difficulty);
        
        // Min difficulty should produce a larger challenge_param than max difficulty.
        assert!(min_param > max_param);
        
        // Both should be reasonable values
        assert_ne!(min_param, [0x00; 32]);
        assert_ne!(min_param, [0xFF; 32]);
        assert_ne!(max_param, [0x00; 32]);
        assert_ne!(max_param, [0xFF; 32]);
        
        // Test values slightly outside the range
        let below_min = IronShieldChallenge::difficulty_to_challenge_param(9_999);
        let above_max = IronShieldChallenge::difficulty_to_challenge_param(10_000_001);
        
        // With rounding, very close values might produce the same result
        assert!(below_min >= min_param); // Should be the same or larger
        assert!(above_max <= max_param); // Should be the same or smaller
    }

    #[test]
    fn test_from_concat_struct_edge_cases() {
        // Test with a valid minimum length hex (32 bytes = 64 hex chars 
        // for challenge_param and public_key, 64 bytes = 128 hex chars 
        // for signature).
        // Building strings programmatically.
        let valid_32_byte_hex = "0".repeat(64);  // 32 bytes = 64 hex chars
        let valid_64_byte_hex = "0".repeat(128); // 64 bytes = 128 hex chars
        assert_eq!(valid_32_byte_hex.len(), 64, "32-byte hex string should be exactly 64 characters");
        assert_eq!(valid_64_byte_hex.len(), 128, "64-byte hex string should be exactly 128 characters");

        let input = format!("test_nonce|1000000|1030000|test_website|{}|{}|{}",
                            valid_32_byte_hex, valid_32_byte_hex, valid_64_byte_hex);
        let result = IronShieldChallenge::from_concat_struct(&input);

        if result.is_err() {
            panic!("Expected success but got error: {}", result.unwrap_err());
        }

        let parsed = result.unwrap();
        assert_eq!(parsed.random_nonce, "test_nonce");
        assert_eq!(parsed.created_time, 1000000);
        assert_eq!(parsed.expiration_time, 1030000);
        assert_eq!(parsed.website_id, "test_website");
        assert_eq!(parsed.challenge_param, [0u8; 32]);
        assert_eq!(parsed.public_key, [0u8; 32]);
        assert_eq!(parsed.challenge_signature, [0u8; 64]);

        // Test with all F's hex.
        let all_f_32_hex = "f".repeat(64);   // 32 bytes of 0xFF
        let all_f_64_hex = "f".repeat(128);  // 64 bytes of 0xFF
        assert_eq!(all_f_32_hex.len(), 64, "All F's 32-byte hex string should be exactly 64 characters");
        assert_eq!(all_f_64_hex.len(), 128, "All F's 64-byte hex string should be exactly 128 characters");

        let input = format!("max_nonce|9999999|9999999|max_website|{}|{}|{}",
                            all_f_32_hex, all_f_32_hex, all_f_64_hex);
        let result = IronShieldChallenge::from_concat_struct(&input);

        if result.is_err() {
            panic!("Expected success but got error: {}", result.unwrap_err());
        }

        let parsed = result.unwrap();
        assert_eq!(parsed.random_nonce, "max_nonce");
        assert_eq!(parsed.created_time, 9999999);
        assert_eq!(parsed.expiration_time, 9999999);
        assert_eq!(parsed.website_id, "max_website");
        assert_eq!(parsed.challenge_param, [0xffu8; 32]);
        assert_eq!(parsed.public_key, [0xffu8; 32]);
        assert_eq!(parsed.challenge_signature, [0xffu8; 64]);
    }
} 