//! # Utility Functions for Serialization and Concatenation with Serde.

use base64::Engine;
use serde::{
    Deserialize,
    Deserializer,
    Serializer,
    de::Error
};

/// Custom serialization for 64-byte arrays (Ed25519 signatures)
///
/// Serializes a fixed-size 64-byte array into a byte sequence
/// suitable for various serialization formats, namely, JSON.
///
/// # Arguments
/// * `signature`:  A reference to a 64-byte array representing
///                 an Ed25519 signature.
/// * `serializer`: The serde serializer instance that handles
///                 the serialization format.
///
/// # Returns
/// * `Result<S::Ok, S::Error>`: Success value from the serializer
///                              or a serialization error if the
///                              operation fails.
///
/// # Type Parameters
/// * `S`: The serializer type that implements the `Serializer`
///        trait.
///
/// # Example
/// ```
/// use ironshield_types::serialize_signature;
///
/// #[derive(serde::Serialize)]
/// struct SignedMessage {
///     #[serde(serialize_with = "serialize_signature")]
///     signature: [u8; 64],
/// }
/// ```
pub fn serialize_signature<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(signature)
}

/// Custom deserialization for 64-byte arrays (Ed25519 signatures)
///
/// Deserializes a byte sequence back into a fixed-size 64-byte array
/// with strict length validation to ensure cryptographic "correctness".
///
/// # Arguments
/// * `deserializer`: The serde deserializer instance that
///                   handles the actual deserialization.
///
/// # Returns
/// * `Result<[u8; 64], D::Error>`: A 64-byte array on success,
///                                 or a deserialization error
///                                 if the operation fails or
///                                 the byte length is incorrect.
///
/// # Type Parameters
/// * `D`: The deserializer type that implements the `Deserializer`
///        trait.
///
/// # Errors
/// * Returns a custom error if the deserialized byte sequence is
///   not exactly 64 bytes long. (Requirement in the Ed25519 standard.)
///
/// # Example
/// ```
/// use ironshield_types::deserialize_signature;
///
/// #[derive(serde::Deserialize)]
/// struct SignedMessage {
///     #[serde(deserialize_with = "deserialize_signature")]
///     signature: [u8; 64],
/// }
/// ```
pub fn deserialize_signature<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

    if bytes.len() != 64 {
        return Err(Error::custom(format!("Expected 64 bytes, got {}", bytes.len())));
    }

    let mut array = [0u8; 64];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Custom serialization for 32-byte arrays (challenge params, public keys).
///
/// Serializes a fixed-size 32-byte array into a byte sequence
/// suitable for various serialization formats.
///
/// # Arguments
/// * `bytes`:      A reference to a 32-byte array representing
///                 cryptographic data such as public keys or
///                 challenge parameters.
/// * `serializer`: The serde serializer instance that will
///                 handle the actual serialization format.
///
/// # Returns
/// * `Result<S::Ok, S::Error>`: Success value from the serializer
///                              or a serialization error if
///                              the operation fails.
///
/// # Type Parameters
/// * `S`: The serializer type that implements the `Serializer` trait.
///
/// # Example
/// ```
/// use ironshield_types::serialize_32_bytes;
///
/// #[derive(serde::Serialize)]
/// struct CryptoKey {
///     #[serde(serialize_with = "serialize_32_bytes")]
///     public_key: [u8; 32],
/// }
/// ```
pub fn serialize_32_bytes<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

/// Custom serialization for 32-byte arrays (challenge params, public keys)
///
/// Deserializes a byte sequence back into a fixed-size 32-byte array,
/// with strict length validation to ensure cryptographic correctness.
///
/// # Arguments
/// * `deserializer`: The serde deserializer instance that will
///                   handle the actual deserialization from the
///                   source format.
///
/// # Returns
/// * `Result<[u8; 32], D::Error>`: A 32-byte array on success,
///                                 or a deserialization error
///                                 if the operation fails or
///                                 the byte length is incorrect.
///
/// # Type Parameters
/// * `D`: The deserializer type that implements the `Deserializer`
///        trait.
///
/// # Errors
/// * Returns a custom error if the deserialized byte sequence
///   is not exactly 32 bytes long, (Requirement of the
///   cryptographic primitive in use.)
///
/// # Example
/// ```
/// use ironshield_types::deserialize_32_bytes;
///
/// #[derive(serde::Deserialize)]
/// struct CryptoKey {
///     #[serde(deserialize_with = "deserialize_32_bytes")]
///     public_key: [u8; 32],
/// }
/// ```
pub fn deserialize_32_bytes<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
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
    let decoded_bytes: Vec<u8> = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_string)
        .map_err(|e: base64::DecodeError| format!("Base64 decode error: {}", e))?;

    String::from_utf8(decoded_bytes)
        .map_err(|e: std::string::FromUtf8Error| format!("UTF-8 conversion error: {}", e))
}