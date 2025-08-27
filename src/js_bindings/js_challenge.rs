use crate::IronShieldChallenge;

#[cfg(any(feature = "wasm", rust_analyzer))]
use wasm_bindgen::prelude::*;

/// JavaScript-compatible wrapper for `IronShieldChallenge`
/// with JSON serialization.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub struct JsIronShieldChallenge {
    inner: IronShieldChallenge,
}

#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
impl JsIronShieldChallenge {
    /// Creates a new JavaScript binding for the `IronShieldChallenge`
    /// from a JSON string.
    ///
    /// Constructor is `from_json(...)` because `IronShieldChallenge` is
    /// intended (typically) to be received from a server as JSON,
    /// not created directly in JavaScript or created by the user.
    ///
    /// # Arguments
    /// * `json_str`: JSON representation of the challenge.
    ///
    /// # Returns
    /// * `Result<JsIronShieldChallenge, JsValue>`: A wrapped challenge
    ///                                             or an error if parsing fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(constructor)]
    pub fn from_json(json_str: &str) -> Result<Self, JsValue> {
        let challenge: IronShieldChallenge = serde_json::from_str(json_str)
            .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;

        Ok(JsIronShieldChallenge { inner: challenge })
    }

    /// Creates a response from a Base64 URL-safe encoded header string-value.
    ///
    /// # Arguments
    /// * `encoded_header_value`: The Base64 URL-safe encoded string to decode.
    ///
    /// # Returns
    /// * `Result<JsIronShieldChallenge, JsValue>`: Decoded challenge or an
    ///                                             error if decoding fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn from_base64url_header(encoded_header_value: &str) -> Result<Self, JsValue> {
        let challenge: IronShieldChallenge = IronShieldChallenge::from_base64url_header(encoded_header_value)
            .map_err(|e: String| JsValue::from_str(&format!("Failed to decode Base64 URL-safe header: {}", e)))?;

        Ok(Self { inner: challenge })
    }

    /// Creates a challenge from a concatenated string.
    ///
    /// # Arguments
    /// * `concat_str`: Pipe-delimited string representation.
    ///
    /// # Returns
    /// * `Result<JsIronShieldChallenge, JsValue>`: Parsed challenge or error.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn from_concat_struct(concat_str: &str) -> Result<JsIronShieldChallenge, JsValue> {
        let challenge: IronShieldChallenge = IronShieldChallenge::from_concat_struct(concat_str)
            .map_err(|e: String| JsValue::from_str(&format!("Failed to parse concat string: {}", e)))?;
        Ok(JsIronShieldChallenge { inner: challenge })
    }

    /// Converts the `JsIronShieldChallenge` to a JSON string.
    ///
    /// # Returns
    /// * `Result<String, JsValue>`: A JSON string representation of the challenge
    ///                              or an error if serialization fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Failed to serialize challenge to JSON: {}", e)))
    }

    /// Converts the challenge to a JavaScript object.
    ///
    /// # Returns
    /// * `Result<JsValue, JsValue>`: JavaScript object or error
    ///                               if serialization fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn to_js_object(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner)
            .map_err(|e: serde_wasm_bindgen::Error| JsValue::from_str(&format!("Failed to convert challenge to JS object: {:?}", e)))
    }

    /// Encodes the challenge as a Base64 URL-safe string
    /// without padding.
    ///
    /// # Returns
    /// * `String`: A Base64 URL-safe encoded string of the challenge.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn to_base64url_header(&self) -> String {
        self.inner.to_base64url_header()
    }
    
    /// # Returns
    /// * `String`: The random nonce as a string.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn random_nonce(&self) -> String {
        self.inner.random_nonce.clone()
    }

    /// # Returns
    /// * `i64`: The creation time as an i64 Unix timestamp.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn created_time(&self) -> i64 {
        self.inner.created_time
    }

    /// # Returns
    /// * `i64`: The expiration time as an i64 Unix timestamp.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn expiration_time(&self) -> i64 {
        self.inner.expiration_time
    }

    /// # Returns
    /// * `String` The website ID string.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn website_id(&self) -> String {
        self.inner.website_id.clone()
    }

    /// # Returns
    /// * `Vec<u8>`: The challenge parameter as raw bytes.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn challenge_param(&self) -> Vec<u8> {
        self.inner.challenge_param.to_vec()
    }

    /// # Returns
    /// * `String`: The challenge parameter encoded as a hexadecimal string.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn challenge_param_hex(&self) -> String {
        hex::encode(self.inner.challenge_param)
    }

    /// # Returns
    /// * `u64`: The recommended number of attempts for this challenge.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn recommended_attempts(&self) -> u64 {
        self.inner.recommended_attempts
    }

    /// # Returns
    /// * `Vec<u8>`: The public key as raw bytes.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.to_vec()
    }

    /// # Returns
    /// * `String`: The public key encoded as a hexadecimal string.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.public_key)
    }

    /// # Returns
    /// * `Vec<u8>`: The challenge signature as raw bytes.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn challenge_signature(&self) -> Vec<u8> {
        self.inner.challenge_signature.to_vec()
    }

    /// # Returns
    /// * `String`: The challenge signature encoded as a hexadecimal string.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn challenge_signature_hex(&self) -> String {
        hex::encode(self.inner.challenge_signature)
    }

    /// Checks if the challenge has expired.
    ///
    /// # Returns
    /// * `bool`: `true` if expired, `false` otherwise.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Returns milliseconds until the challenge expires.
    ///
    /// # Returns
    /// * `i64`: Milliseconds until expiration (negative if already expired).
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn time_until_expiration(&self) -> i64 {
        self.inner.time_until_expiration()
    }

    /// Concatenates all challenge fields into a pipe-delimited string.
    ///
    /// # Returns
    /// * `String`: Concatenated string representation of the challenge.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn concat_struct(&self) -> String {
        self.inner.concat_struct()
    }

    /// Generates the current time in milliseconds.
    ///
    /// # Returns
    /// * `i64`: Current Unix timestamp in milliseconds.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn generate_created_time() -> i64 {
        IronShieldChallenge::generate_created_time()
    }

    /// Generates a random nonce as a hex string.
    ///
    /// # Returns
    /// * `String`: Random hex-encoded nonce.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn generate_random_nonce() -> String {
        IronShieldChallenge::generate_random_nonce()
    }

    /// Calculates recommended attempts for a given difficulty.
    ///
    /// # Arguments
    /// * `difficulty`: Target difficulty level.
    ///
    /// # Returns
    /// * `u64`: Recommended number of attempts (2x the difficulty).
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn recommended_attempts_for_difficulty(difficulty: u64) -> u64 {
        IronShieldChallenge::recommended_attempts(difficulty)
    }

    /// Converts difficulty to challenge parameter bytes.
    ///
    /// # Arguments
    /// * `difficulty`: Target difficulty level.
    ///
    /// # Returns
    /// * `Vec<u8>`: 32-byte challenge parameter array.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn difficulty_to_challenge_param(difficulty: u64) -> Vec<u8> {
        IronShieldChallenge::difficulty_to_challenge_param(difficulty).to_vec()
    }
}