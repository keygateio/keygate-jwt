use base64ct::Base64UrlUnpadded;
use base64ct::Encoding;
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::*;
use crate::common::*;
use crate::ensure;
use crate::error::*;
use crate::jwt_header::*;

pub const MAX_HEADER_LENGTH: usize = 8192;

/// Utilities to get information about a JWT token
pub struct Token;

/// JWT token information useful before signature/tag verification
#[derive(Debug, Clone, Default)]
pub struct TokenMetadata {
    pub(crate) jwt_header: JWTHeader,
}

impl TokenMetadata {
    /// The JWT algorithm for this token ("alg")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. Clients should ignore it and use
    /// the correct type of key directly.
    pub fn algorithm(&self) -> &str {
        &self.jwt_header.algorithm
    }

    /// The content type for this token ("cty")
    pub fn content_type(&self) -> Option<&str> {
        self.jwt_header.content_type.as_deref()
    }

    /// The key, or public key identifier for this token ("kid")
    pub fn key_id(&self) -> Option<&str> {
        self.jwt_header.key_id.as_deref()
    }

    /// The signature type for this token ("typ")
    pub fn signature_type(&self) -> Option<&str> {
        self.jwt_header.signature_type.as_deref()
    }

    /// The set of raw critical properties for this token ("crit")
    pub fn critical(&self) -> Option<&[String]> {
        self.jwt_header.critical.as_deref()
    }

    /// The certificate chain for this token ("x5c")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party.
    pub fn certificate_chain(&self) -> Option<&[String]> {
        self.jwt_header.certificate_chain.as_deref()
    }

    /// The key set URL for this token ("jku")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that the URL belongs to the domain you expect.
    pub fn key_set_url(&self) -> Option<&str> {
        self.jwt_header.key_set_url.as_deref()
    }

    /// The public key for this token ("jwk")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that it's in a set of public keys you already trust.
    pub fn public_key(&self) -> Option<&str> {
        self.jwt_header.public_key.as_deref()
    }

    /// The certificate URL for this token ("x5u")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that the URL belongs to the domain you expect.
    pub fn certificate_url(&self) -> Option<&str> {
        self.jwt_header.certificate_url.as_deref()
    }

    /// URLsafe-base64-encoded SHA256 hash of the X.509 certificate for this
    /// token ("x5t#256") In practice, it can also be any string
    /// representing the public key. This information should not be trusted:
    /// it is unprotected and can be freely modified by a third party.
    pub fn certificate_sha256_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha256_thumbprint.as_deref()
    }
}

impl Token {
    pub(crate) fn build<AuthenticationOrSignatureFn, CustomClaims: Serialize + DeserializeOwned>(
        jwt_header: &JWTHeader,
        claims: JWTClaims<CustomClaims>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<String, JWTError>
    where
        AuthenticationOrSignatureFn: FnOnce(&str) -> Result<Vec<u8>, JWTError>,
    {
        let jwt_header_json = serde_json::to_string(&jwt_header)?;
        let claims_json = serde_json::to_string(&claims)?;
        let authenticated = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(jwt_header_json.as_bytes()),
            Base64UrlUnpadded::encode_string(claims_json.as_bytes())
        );
        let authentication_tag_or_signature = authentication_or_signature_fn(&authenticated)?;
        let mut token = authenticated;
        token.push('.');
        token.push_str(&Base64UrlUnpadded::encode_string(
            &authentication_tag_or_signature,
        ));
        Ok(token)
    }

    pub(crate) fn verify<AuthenticationOrSignatureFn, CustomClaims: Serialize + DeserializeOwned>(
        jwt_alg_name: &'static str,
        token: &str,
        options: Option<VerificationOptions>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<JWTClaims<CustomClaims>, JWTError>
    where
        AuthenticationOrSignatureFn: FnOnce(&str, &[u8]) -> Result<(), JWTError>,
    {
        let options = options.unwrap_or_default();

        if let Some(max_token_length) = options.max_token_length {
            ensure!(token.len() <= max_token_length, JWTError::TokenTooLong);
        }

        let mut parts = token.split('.');
        let jwt_header_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(
            jwt_header_b64.len() <= options.max_header_length.unwrap_or(MAX_HEADER_LENGTH),
            JWTError::HeaderTooLarge
        );
        let claims_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        let authentication_tag_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(parts.next().is_none(), JWTError::CompactEncodingError);
        let jwt_header: JWTHeader =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(jwt_header_b64)?)?;
        if let Some(signature_type) = &jwt_header.signature_type {
            let signature_type_uc = signature_type.to_uppercase();
            ensure!(
                signature_type_uc == "JWT" || signature_type_uc.ends_with("+JWT"),
                JWTError::NotJWT
            );
        }
        ensure!(
            jwt_header.algorithm == jwt_alg_name,
            JWTError::AlgorithmMismatch
        );
        if let Some(required_key_id) = &options.required_key_id {
            if let Some(key_id) = &jwt_header.key_id {
                ensure!(key_id == required_key_id, JWTError::KeyIdentifierMismatch);
            } else {
                return Err(JWTError::MissingJWTKeyIdentifier);
            }
        }
        let authentication_tag = Base64UrlUnpadded::decode_vec(authentication_tag_b64)?;
        let authenticated = &token[..jwt_header_b64.len() + 1 + claims_b64.len()];
        authentication_or_signature_fn(authenticated, &authentication_tag)?;
        let claims: JWTClaims<CustomClaims> =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(claims_b64)?)?;
        claims.validate(&options)?;
        Ok(claims)
    }

    /// Decode token information that can be usedful prior to signature/tag
    /// verification
    pub fn decode_metadata(token: &str) -> Result<TokenMetadata, JWTError> {
        let mut parts = token.split('.');
        let jwt_header_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(
            jwt_header_b64.len() <= MAX_HEADER_LENGTH,
            JWTError::HeaderTooLarge
        );
        let jwt_header: JWTHeader =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(jwt_header_b64)?)?;
        Ok(TokenMetadata { jwt_header })
    }
}

#[test]
fn should_verify_token() {
    use crate::prelude::*;

    let key_pair = Ed25519KeyPair::generate();

    let issuer = "issuer";
    let audience = "recipient";
    let nonce = "some_nonce";
    let claims = Claims::create(Duration::from_mins(10))
        .with_issuer(issuer)
        .with_audience(audience)
        .with_nonce(nonce);

    let token = key_pair.sign(claims).unwrap();

    let options = VerificationOptions {
        required_nonce: Some(nonce.to_string()),
        allowed_issuers: Some(HashSet::from_strings(&[issuer])),
        allowed_audiences: Some(HashSet::from_strings(&[audience])),
        ..Default::default()
    };
    key_pair
        .public_key()
        .verify_token::<NoCustomClaims>(&token, Some(options))
        .unwrap();
}

#[test]
fn multiple_audiences() {
    use std::collections::HashSet;

    use crate::prelude::*;

    let key_pair = Ed25519KeyPair::generate();

    let mut audiences = HashSet::new();
    audiences.insert("audience 1");
    audiences.insert("audience 2");
    audiences.insert("audience 3");
    let claims = Claims::create(Duration::from_mins(10)).with_audiences(audiences);
    let token = key_pair.sign(claims).unwrap();

    let options = VerificationOptions {
        allowed_audiences: Some(HashSet::from_strings(&["audience 1"])),
        ..Default::default()
    };
    key_pair
        .public_key()
        .verify_token::<NoCustomClaims>(&token, Some(options))
        .unwrap();
}

#[test]
fn explicitly_empty_audiences() {
    use std::collections::HashSet;

    use crate::prelude::*;

    let key_pair = Ed25519KeyPair::generate();

    let audiences: HashSet<&str> = HashSet::new();
    let claims = Claims::create(Duration::from_mins(10)).with_audiences(audiences);
    let token = key_pair.sign(claims).unwrap();
    let decoded = key_pair
        .public_key()
        .verify_token::<NoCustomClaims>(&token, None)
        .unwrap();
    assert!(decoded.audiences.is_some());

    let claims = Claims::create(Duration::from_mins(10)).with_audience("");
    let token = key_pair.sign(claims).unwrap();
    let decoded = key_pair
        .public_key()
        .verify_token::<NoCustomClaims>(&token, None)
        .unwrap();
    assert!(decoded.audiences.is_some());

    let claims = Claims::create(Duration::from_mins(10));
    let token = key_pair.sign(claims).unwrap();
    let decoded = key_pair
        .public_key()
        .verify_token::<NoCustomClaims>(&token, None)
        .unwrap();
    assert!(decoded.audiences.is_none());
}
