# IronShield Types

Shared types and utilities for the IronShield Proof-of-Work (PoW) system.

[![Crates.io](https://img.shields.io/crates/v/ironshield-types.svg)](https://crates.io/crates/ironshield-types)
[![Documentation](https://docs.rs/ironshield-types/badge.svg)](https://docs.rs/ironshield-types)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

## Overview

`ironshield-types` provides the core data structures and serialization utilities used across the IronShield ecosystem. This crate defines the fundamental types for challenges, responses, tokens, and cryptographic operations used by IronShield's edge-native DDoS protection system.

## Features

- **Challenge Types**: Structures for proof-of-work challenges with Ed25519 signatures
- **Response Types**: Standardized response formats for PoW solutions  
- **Token Types**: Authentication tokens with expiration and validation
- **Cryptographic Utilities**: Ed25519 signing and verification functions
- **Serialization Support**: Full serde support with WASM compatibility
- **Base64URL Encoding**: Optimized for HTTP header transport

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ironshield-types = "0.1.0"
```

## Quick Start

```rust
use ironshield_types::*;

// Create a challenge
let challenge = IronShieldChallenge::new(
    "random_nonce_123".to_string(),
    chrono::Utc::now().timestamp_millis(),
    "example.com".to_string(),
    [0x12; 32], // challenge_param
    [0x34; 32], // public_key  
    [0x56; 64], // signature
);

// Serialize for transport
let json = serde_json::to_string(&challenge)?;

// Encode for HTTP headers
let header_value = challenge.to_base64url_header();
```

## Core Types

### IronShieldChallenge
Represents a proof-of-work challenge with cryptographic verification:
- Random nonce and timing parameters
- Difficulty threshold and attempt recommendations  
- Ed25519 public key and signature
- Base64URL encoding for HTTP transport

### IronShieldChallengeResponse
Contains the solution to a PoW challenge:
- Challenge signature (for verification)
- Solution nonce that satisfies the difficulty

### IronShieldToken
Authentication token for verified PoW completion:
- Challenge signature reference
- Validity timestamp
- Authentication signature

## Cryptographic Operations

The crate includes utilities for Ed25519 operations:

```rust
use ironshield_types::*;

// Sign a challenge (server-side)
let signed_challenge = create_signed_challenge(
    "nonce".to_string(),
    timestamp,
    "website.com".to_string(), 
    difficulty_params,
)?;

// Verify a challenge (client-side)
verify_challenge_signature(&challenge)?;
validate_challenge(&challenge)?; // includes expiration check
```

## WASM Support

All types are fully compatible with WebAssembly:

```rust
use wasm_bindgen::prelude::*;
use ironshield_types::*;

#[wasm_bindgen]
pub fn parse_challenge(header: &str) -> Result<IronShieldChallenge, JsValue> {
    IronShieldChallenge::from_base64url_header(header)
        .map_err(|e| JsValue::from_str(&e))
}
```

## License

This project is licensed under the [Business Source License 1.1](LICENSE). 
It will automatically convert to Apache-2.0 on July 24, 2028.

## Contributing

See the main [IronShield repository](https://github.com/IronShield-Tech/IronShield) for contribution guidelines. 