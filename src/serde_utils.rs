use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

/// Custom serialization for 64-byte arrays (Ed25519 signatures).
pub fn serialize_signature<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(signature)
}

/// Custom deserialization for 64-byte arrays (Ed25519 signatures).
pub fn deserialize_signature<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

    if bytes.len() != 64 {
        return Err(Error::custom(format!("Expected 64 bytes, got {}", bytes.len())));
    }

    let mut array = [0u8; 64];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Custom serialization for 32-byte arrays (challenge params, public keys).
pub fn serialize_32_bytes<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

/// Custom deserialization for 32-byte arrays (challenge params, public keys).
pub fn deserialize_32_bytes<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

    if bytes.len() != 32 {
        return Err(Error::custom(format!("Expected 32 bytes, got {}", bytes.len())));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Encodes a concatenated string into a Base64 URL-safe
/// format without padding.
///
/// Intended for use with a concatenated string generated
/// from the function `concat_struct`.
/// Encodes using base64url encoding (RFC 4648, Section 5).
///
/// # Arguments
/// * `concat_string`: The string to be encoded, typically
///                    concatenated from the function
///                    `concat_struct`.
///
/// # Returns
/// * A Base64 URL-safe encoded string without padding.
pub fn concat_struct_base64url_encode(concat_string: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(concat_string.as_bytes())
}

/// Decodes a Base64 URL-safe encoded string into a
/// concatenated string.
///
/// Intended for use with a Base64 URL-safe encoded string
/// generated from the function
/// `concat_struct_base64url_encode`.
///
/// # Arguments
/// * `encoded_string`: The Base64 URL-safe encoded string
///                     to decode.
///
/// # Returns
/// * A Result containing the decoded string or an error
///   if decoding fails.
///
/// # Errors
/// * Returns a `base64::DecodeError` if the input string
///   is not valid Base64 URL-safe encoded.
pub fn concat_struct_base64url_decode(encoded_string: String) -> Result<String, String> {
    let decoded_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_string)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    String::from_utf8(decoded_bytes)
        .map_err(|e| format!("UTF-8 conversion error: {}", e))
}