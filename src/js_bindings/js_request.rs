//! # JavaScript binding functionality for the IronShieldRequest (IronShieldRequest struct)

use crate::IronShieldRequest;

#[cfg(any(feature = "wasm", rust_analyzer))]
use wasm_bindgen::prelude::*;

/// JavaScript-compatible wrapper for `IronShieldRequest`
/// with JSON serialization.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub struct JsIronShieldRequest {
    inner: IronShieldRequest,
}

#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
impl JsIronShieldRequest {
    /// Creates a new JavaScript that can be called with 
    /// `new JsIronShieldRequest()`.
    /// 
    /// The `IronShieldRequest` is incorporating `new(...)` as the
    /// constructor because it is intended to be created
    /// from individual components on the client side,
    /// rather than being received from a server,
    /// and therefore does not have a `from_json` constructor.
    /// 
    /// # Arguments
    /// * `endpoint`:  The endpoint URL for the request.
    /// * `timestamp`: The timestamp of the request in unix millis.
    /// 
    /// # Returns
    /// * `Result<Self, JsValue>`: New request or an error.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        endpoint: &str,
        timestamp: i64
    ) -> Result<Self, JsValue> {
        if endpoint.is_empty() {
            return Err(JsValue::from_str("Endpoint cannot be empty"));
        }
        if timestamp <= 0 {
            return Err(JsValue::from_str("Timestamp must be within the bounds of a valid Unix timestamp in milliseconds"));
        }
        
        let request = IronShieldRequest::new(endpoint.to_string(), timestamp);
        Ok(Self { inner: request })
    }
    
    /// Creates a new JavaScript binding for the `IronShieldRequest`
    /// from a JSON string.
    /// 
    /// # Arguments
    /// * `json_str`: JSON representation of the request.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldRequest, JsValue>`: A wrapped request
    ///                                           or an error if parsing fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn from_json(json_str: &str) -> Result<Self, JsValue> {
        let request: IronShieldRequest = serde_json::from_str(json_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;
        
        Ok(Self { inner: request })
    }
    
    /// Converts the `JsIronShieldRequest` to a JSON string.
    /// 
    /// # Returns
    /// * `Result<String, JsValue>`: A JSON string representation of the request
    ///                              or an error if serialization fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize request: {}", e)))
    }
    
    /// Converts the request to a JavaScript object.
    /// 
    /// # Returns
    /// * `Result<JsValue, JsValue>`: JavaScript object or error
    ///                               if serialization fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn to_js_object(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert request to JS object: {:?}", e)))
    }
    
    /// Encodes the request as a Base64 URL-safe string
    /// without padding.
    /// 
    /// # Returns
    /// * `String`: A Base64 URL-safe encoded string of the request.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn to_base64url_header(&self) -> String {
        self.inner.to_base64url_header()
    }
    
    /// Creates a request from a Base64 URL-safe encoded header string-value.
    /// 
    /// # Arguments
    /// * `encoded_header_value`: The Base64 URL-safe encoded string to decode.
    /// 
    /// # Returns
    /// * `Result<JsIronShieldRequest, JsValue>`: Decoded request or an
    ///                                           error if decoding fails.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen]
    pub fn from_base64url_header(encoded_header_value: &str) -> Result<Self, JsValue> {
        let request = IronShieldRequest::from_base64url_header(encoded_header_value)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode Base64 URL-safe header: {}", e)))?;
        
        Ok(Self { inner: request })
    }
    
    /// # Returns
    /// * `String`: The challenge endpoint of the request.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn endpoint(&self) -> String {
        self.inner.endpoint.clone()
    }
    
    /// # Returns
    /// * `i64`: The timestamp of the request.
    #[cfg(any(feature = "wasm", rust_analyzer))]
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> i64 {
        self.inner.timestamp
    }
}