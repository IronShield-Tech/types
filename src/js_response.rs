//! # JavaScript binding functionality for the IronShield Challenge Response (IronShieldChallengeResponse struct)

use wasm_bindgen::prelude::*;
use crate::IronShieldChallengeResponse;

/// JavaScript-compatible wrapper for IronShieldChallengeResponse
/// with JSON serialization.
#[wasm_bindgen]
pub struct JsIronShieldChallengeResponse {
    inner: IronShieldChallengeResponse,
}

#[wasm_bindgen]
impl JsIronShieldChallengeResponse {
    /// Creates a new JavaScript binding for the `IronShieldChallengeResponse`.
    /// 
    /// # Arguments
    /// * `json_str`: JSON representation of the response.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldResponse, JsValue>`: A wrapped response 
    ///                                            or an error if parsing fails.
    #[wasm_bindgen(constructor)]
    pub fn from_json(json_str: &str) -> Result<Self, JsValue> {
        let response: IronShieldChallengeResponse = serde_json::from_str(json_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;
        
        Ok(JsIronShieldChallengeResponse { inner: response })
    }
    
    /// Converts the `JsIronShieldResponse` to a JSON string.
    /// 
    /// # Returns
    /// * `Result<String, JsValue>`: A JSON string representation of the response
    ///                              or an error if serialization fails.
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize response to JSON: {}", e)))
    }
    
    /// Converts the response to a JavaScript object.
    ///
    /// # Returns
    /// * `Result<JsValue, JsValue>`: JavaScript object or error.
    #[wasm_bindgen]
    pub fn to_js_object(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert response to JS object: {:?}", e)))
    }
    
    /// Encodes the challenge as a Base64 URL-safe string
    /// without padding.
    /// 
    /// # Returns
    /// * `String`: A Base64 URL-safe encoded string of the challenge.
    #[wasm_bindgen]
    pub fn to_base64url_header(&self) -> String {
        self.inner.to_base64url_header()
    }
    
    
    /// Creates a response from a Base64 URL-safe encoded header string-value.
    /// 
    /// # Arguments
    /// * `encoded_header_value`: The Base64 URL-safe encoded string to decode.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldResponse, JsValue>`: Decoded response or an
    ///                                            error if decoding fails.
    #[wasm_bindgen]
    pub fn from_base64url_header(encoded_header_value: &str) -> Result<Self, JsValue> {
        let response = IronShieldChallengeResponse::from_base64url_header(encoded_header_value)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode Base64 URL-safe header: {}", e)))?;
        
        Ok(Self { inner: response })
    }

    /// Gets the challenge signature as hex string.
    #[wasm_bindgen(getter)]
    pub fn challenge_signature_hex(&self) -> String {
        hex::encode(self.inner.challenge_signature)
    }

    /// Gets the solution nonce.
    #[wasm_bindgen(getter)]
    pub fn solution(&self) -> i64 {
        self.inner.solution
    }
}