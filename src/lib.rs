// [![GitHub CI](https://github.com/keygateio/keygate-jwt/workflows/Rust/badge.svg)](https://github.com/keygateio/keygate-jwt/actions)
// [![Docs.rs](https://docs.rs/keygate-jwt/badge.svg)](https://docs.rs/keygate-jwt/)
// [![crates.io](https://img.shields.io/crates/v/keygate-jwt.svg)](https://crates.io/crates/keygate-jwt)//!
//! # keygate-jwt
//!
//! A new JWT implementation for Rust that focuses on simplicity, while avoiding
//! common JWT security pitfalls.
//!
//! A new JWT (JSON Web Tokens) implementation for Rust that focuses on simplicity, while avoiding common JWT security pitfalls.
//!
//! * p256
//!   * `ES256`
//! * p384
//!   * `ES384`
//! * secp256k1
//!   * `ES256K`
//! * Ed25519
//!   * `EdDSA`
//!
//! `keygate-jwt` uses only pure Rust implementations, and can be compiled out of the box to WebAssembly/WASI.
//!
//! Important: JWT's purpose is to verify that data has been created by a party
//! knowing a secret key. It does not provide any kind of confidentiality: JWT
//! data is simply encoded as BASE64, and is not encrypted.

#![forbid(unsafe_code)]

pub mod algorithms;
pub mod claims;
pub mod common;
pub mod token;

mod jwt_header;
mod serde_additions;

mod error;
pub use error::{Error, JWTError};

pub mod prelude {
    pub use std::collections::HashSet;

    pub use coarsetime::{self, Clock, Duration, UnixTimeStamp};
    pub use ct_codecs::{
        Base64, Base64NoPadding, Base64UrlSafe, Base64UrlSafeNoPadding, Decoder as _, Encoder as _,
    };
    pub use serde::{Deserialize, Serialize};

    pub use crate::algorithms::*;
    pub use crate::claims::*;
    pub use crate::common::*;
    pub use crate::token::*;

    mod hashset_from_strings {
        use std::collections::HashSet;

        pub trait HashSetFromStringsT {
            /// Create a set from a list of strings
            fn from_strings(strings: &[impl ToString]) -> HashSet<String> {
                strings.iter().map(|x| x.to_string()).collect()
            }
        }

        impl HashSetFromStringsT for HashSet<String> {}
    }

    pub use hashset_from_strings::HashSetFromStringsT as _;
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[cfg(feature = "ecdsa")]
    #[test]
    fn es256() {
        let key_pair = ES256KeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn es384() {
        let key_pair = ES384KeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn es256k() {
        let key_pair = ES256kKeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn ed25519() {
        #[derive(Serialize, Deserialize)]
        struct CustomClaims {
            is_custom: bool,
        }

        let key_pair = Ed25519KeyPair::generate();
        let mut pk = key_pair.public_key();
        let key_id = pk.create_key_id();
        let key_pair = key_pair.with_key_id(key_id);
        let custom_claims = CustomClaims { is_custom: true };
        let claims = Claims::with_custom_claims(custom_claims, Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let options = VerificationOptions {
            required_key_id: Some(key_id.to_string()),
            ..Default::default()
        };
        let claims: JWTClaims<CustomClaims> = key_pair
            .public_key()
            .verify_token::<CustomClaims>(&token, Some(options))
            .unwrap();
        assert!(claims.custom.is_custom);
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn ed25519_der() {
        let key_pair = Ed25519KeyPair::generate();
        let der = key_pair.to_der();
        let key_pair2 = Ed25519KeyPair::from_der(&der).unwrap();
        assert_eq!(key_pair.to_bytes(), key_pair2.to_bytes());
    }

    #[test]
    fn require_nonce() {
        let key_pair = Ed25519KeyPair::generate();
        let nonce = "some-nonce".to_string();
        let claims = Claims::create(Duration::from_hours(1)).with_nonce(nonce.clone());
        let token = key_pair.sign(claims).unwrap();

        let options = VerificationOptions {
            required_nonce: Some(nonce),
            ..Default::default()
        };
        key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn eddsa_pem() {
        let sk_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMXY1NUbUe/3dW2YUoKW5evsnCJPMfj60/q0RzGne3gg
-----END PRIVATE KEY-----\n";
        let pk_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyrRjJfTnhMcW5igzYvPirFW5eUgMdKeClGzQhd4qw+Y=
-----END PUBLIC KEY-----\n";
        let kp = Ed25519KeyPair::from_pem(sk_pem).unwrap();
        assert_eq!(kp.public_key().to_pem(), pk_pem);
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn key_metadata() {
        let mut key_pair = Ed25519KeyPair::generate();
        let thumbprint = key_pair.public_key().sha256_thumbprint();
        let key_metadata = KeyMetadata::default()
            .with_certificate_sha256_thumbprint(&thumbprint)
            .unwrap();
        key_pair.attach_metadata(key_metadata).unwrap();

        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();

        let decoded_metadata = Token::decode_metadata(&token).unwrap();
        assert_eq!(
            decoded_metadata.certificate_sha256_thumbprint(),
            Some(thumbprint.as_ref())
        );
        let _ = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    #[test]
    fn expired_token() {
        let key_pair = Ed25519KeyPair::generate();
        let claims = Claims::create(Duration::from_secs(1));
        let token = key_pair.sign(claims).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let options = VerificationOptions {
            time_tolerance: None,
            ..Default::default()
        };
        let claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None);
        assert!(claims.is_ok());
        let claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, Some(options));
        assert!(claims.is_err());
    }
}
