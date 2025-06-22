//! # JavaScript binding functionality for the IronShield Token (IronShieldToken struct)

use wasm_bindgen::prelude::*;
use crate::IronShieldToken;

/// JavaScript-compatible wrapper for IronShieldToken
/// with JSON serialization.
#[wasm_bindgen]
pub struct JsIronShieldToken {
    inner: IronShieldToken,
}

#[wasm_bindgen]
impl JsIronShieldToken {
    /// Creates a new JavaScript binding for the `IronShieldToken` 
    /// from a JSON string.
    ///
    /// Constructor is `from_json` because `IronShieldToken`
    /// is intended (typically) to be received from a server as JSON,
    /// not created directly in JavaScript or created by the user.
    ///
    /// # Arguments
    /// * `json_str` - JSON representation of the token
    ///
    /// # Returns
    /// * `Result<Self, JsValue>` - Parsed token or error
    #[wasm_bindgen]
    pub fn from_json(json_str: &str) -> Result<Self, JsValue> {
        let token: IronShieldToken = serde_json::from_str(json_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse token JSON: {}", e)))?;

        Ok(Self { inner: token })
    }
    
    /// Converts the `JsIronShieldToken` to a JSON string.
    /// 
    /// # Returns
    /// * `Result<String, JsValue>`: A JSON string representation of the token
    ///                              or an error if serialization fails.
    #[wasm_bindgen]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize token to JSON: {}", e)))
    }
    
    /// Converts the token to a JavaScript object.
    /// 
    /// # Returns
    /// * `Result<JsValue, JsValue>`: JavaScript object or error
    ///                               if serialization fails.
    #[wasm_bindgen]
    pub fn to_js_object(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert token to JS object: {:?}", e)))
    }
    
    /// Encodes the token as a Base64 URL-safe string
    /// without padding.
    /// 
    /// # Returns
    /// * `String`: A Base64 URL-safe encoded string of the token.
    #[wasm_bindgen]
    pub fn to_base64url_header(&self) -> String {
        self.inner.to_base64url_header()
    }
    
    /// Creates a token from a Base64 URL-safe encoded header string-value.
    /// 
    /// # Arguments
    /// * `encoded_header_value`: The Base64 URL-safe encoded string to decode.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldToken, JsValue>`: Decoded token or an
    ///                                         error if decoding fails.
    #[wasm_bindgen]
    pub fn from_base64url_header(encoded_header_value: &str) -> Result<Self, JsValue> {
        let token = IronShieldToken::from_base64url_header(encoded_header_value)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode Base64 URL-safe header: {}", e)))?;
        
        Ok(Self { inner: token })
    }

    /// Gets the challenge signature as hex string.
    #[wasm_bindgen(getter)]
    pub fn challenge_signature_hex(&self) -> String {
        hex::encode(self.inner.challenge_signature)
    }

    /// Gets the validity period.
    #[wasm_bindgen(getter)]
    pub fn valid_for(&self) -> i64 {
        self.inner.valid_for
    }

    /// Gets the public key as hex string.
    #[wasm_bindgen(getter)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.public_key)
    }

    /// Gets the authentication signature as hex string.
    #[wasm_bindgen(getter)]
    pub fn authentication_signature_hex(&self) -> String {
        hex::encode(self.inner.auth_signature)
    }
}

