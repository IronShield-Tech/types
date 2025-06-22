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
    /// This creates a JavaScript constructor that can be called with `new JsIronShieldToken()`.
    /// 
    /// The `IronShieldToken` is incorporating `new` as the constructor
    /// because it is intended to be created from individual components
    /// on the client side, rather than being received from a server, 
    /// and therefore does not have a `from_json` constructor.
    ///
    /// # Arguments
    /// * `challenge_signature_hex`:  Challenge signature as hex string
    /// * `valid_for`:                Validity period in milliseconds
    /// * `public_key_hex`:           Public key as hex string
    /// * `auth_signature_hex`:       Authentication signature as hex string
    ///
    /// # Returns
    /// * `Result<JsIronShieldToken, JsValue>`: New token or error
    #[wasm_bindgen(constructor)]
    pub fn new(
        challenge_signature_hex: &str,
        valid_for:               i64,
        public_key_hex:          &str,
        auth_signature_hex:      &str,
    ) -> Result<Self, JsValue> {
        // Parse challenge signature.
        let challenge_signature_bytes = hex::decode(challenge_signature_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid challenge signature hex: {}", e)))?;
        if challenge_signature_bytes.len() != 64 {
            return Err(JsValue::from_str("Challenge signature must be exactly 64 bytes"));
        }
        let mut challenge_signature = [0u8; 64];
        challenge_signature.copy_from_slice(&challenge_signature_bytes);

        // Parse public key.
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key hex: {}", e)))?;
        if public_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Public key must be exactly 32 bytes"));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_key_bytes);

        // Parse authentication signature.
        let auth_signature_bytes = hex::decode(auth_signature_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid authentication signature hex: {}", e)))?;
        if auth_signature_bytes.len() != 64 {
            return Err(JsValue::from_str("Authentication signature must be exactly 64 bytes"));
        }
        let mut auth_signature = [0u8; 64];
        auth_signature.copy_from_slice(&auth_signature_bytes);

        let token = IronShieldToken::new(challenge_signature, valid_for, public_key, auth_signature);
        Ok(Self { inner: token })
    }

    /// Creates a new JavaScript binding for the `IronShieldToken` 
    /// from a JSON string.
    ///
    /// # Arguments
    /// * `json_str` - JSON representation of the token
    ///
    /// # Returns
    /// * `Result<JsIronShieldToken, JsValue>` - Parsed token or error
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

