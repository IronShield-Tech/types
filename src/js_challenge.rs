//! # JavaScript binding functionality for the IronShield Challenge (IronShieldChallenge struct)

use serde_json;
use wasm_bindgen::prelude::*;
use crate::IronShieldChallenge;

/// JavaScript-compatible wrapper for IronShieldChallenge
/// with JSON serialization.
#[wasm_bindgen]
pub struct JsIronShieldChallenge {
    inner: IronShieldChallenge,
}

#[wasm_bindgen]
impl JsIronShieldChallenge {
    /// Creates a new JavaScript binding for the `IronShieldChallenge`.
    /// 
    /// # Arguments
    /// * `json_str`: JSON representation of the challenge.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldChallenge, JsValue>`: A wrapped challenge 
    ///                                             or an error if parsing fails.
    #[wasm_bindgen(constructor)]
    pub fn from_json(json_str: &str) -> Result<Self, JsValue> {
        let challenge: IronShieldChallenge = serde_json::from_str(json_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;
        
        Ok(JsIronShieldChallenge { inner: challenge })
    }
    
    /// Converts the `JsIronShieldChallenge` to a JSON string.
    /// 
    /// # Returns
    /// * `Result<String, JsValue>`: A JSON string representation of the challenge
    ///                              or an error if serialization fails.
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize challenge to JSON: {}", e)))
    }

    /// Converts the challenge to a JavaScript object.
    ///
    /// # Returns
    /// * `Result<JsValue, JsValue>`: JavaScript object or error
    #[wasm_bindgen]
    pub fn to_js_object(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert challenge to JS object: {:?}", e)))
    }
    
    /// Encodes the challenge to a Base64 URL-safe string 
    /// without padding.
    /// 
    /// # Returns
    /// * `String`: A Base64 URL-safe encoded string of the challenge.
    #[wasm_bindgen]
    pub fn to_base64url_header(&self) -> String {
        self.inner.to_base64url_header()
    }
    
    /// Verifies the challenge from a Base64 URL-safe encoded header value.
    /// 
    /// # Arguments
    /// * `encoded_header_value`: The Base64 URL-safe encoded string to decode.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldChallenge, JsValue>`: Decoded challenge or an 
    ///                                             error if decoding fails.
    #[wasm_bindgen]
    pub fn from_base64url_header(encoded_header_value: &str) -> Result<Self, JsValue> {
        let challenge = IronShieldChallenge::from_base64url_header(encoded_header_value)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode Base64 URL-safe header: {}", e)))?;
        
        Ok(JsIronShieldChallenge { inner: challenge })
    }
    
    /// Gets the random nonce as a string.
    #[wasm_bindgen(getter)]
    pub fn random_nonce(&self) -> String {
        self.inner.random_nonce.clone()
    }
    
    /// Gets the difficulty of the challenge as an i64.
    #[wasm_bindgen(getter)]
    pub fn created_time(&self) -> i64 {
        self.inner.created_time
    }
    
    /// Gets the expiration time of the challenge as an i64.
    #[wasm_bindgen(getter)]
    pub fn expiration_time(&self) -> i64 {
        self.inner.expiration_time
    }

    /// Gets the website ID.
    #[wasm_bindgen(getter)]
    pub fn website_id(&self) -> String {
        self.inner.website_id.clone()
    }

    /// Gets the challenge parameter as hex string.
    #[wasm_bindgen(getter)]
    pub fn challenge_param_hex(&self) -> String {
        hex::encode(self.inner.challenge_param)
    }

    /// Gets the public key as hex string.
    #[wasm_bindgen(getter)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.public_key)
    }

    /// Gets the challenge signature as hex string.
    #[wasm_bindgen(getter)]
    pub fn challenge_signature_hex(&self) -> String {
        hex::encode(self.inner.challenge_signature)
    }
}
