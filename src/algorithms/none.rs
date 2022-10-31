use std::vec;

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    claims::JWTClaims,
    common::{KeyMetadata, VerificationOptions},
    jwt_header::JWTHeader,
    token::Token,
    JWTError,
};

/// This algorithm is disabled by default and should never be used to on its own.
/// It can however be useful for non security relevant data.
/// JWTs created with the `none` algorithm are not verified and can be tampered with.
pub struct NoneAlgorithm {
    metadata: Option<KeyMetadata>,
}

pub trait NoneLike {
    fn jwt_alg_name() -> &'static str;
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), JWTError>;

    /// create creates a JWT without verifying the claims.
    /// this code is not unsafe!
    /// none is not a secure algorithm and thus you need to make a conscious decision to use it
    #[allow(unsafe_code)]
    unsafe fn create<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, JWTError> {
        let jwt_header =
            JWTHeader::new(Self::jwt_alg_name().to_string(), None).with_metadata(self.metadata());
        Token::build(&jwt_header, claims, |_| Ok(vec![]))
    }

    /// parse_token parses a JWT without verifying the claims.
    /// this code is not unsafe!
    /// none is not a secure algorithm and thus you need to make a conscious decision to use it
    #[allow(unsafe_code)]
    unsafe fn parse_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, JWTError> {
        Token::verify(Self::jwt_alg_name(), token, options, |_, _| Ok(()))
    }
}

impl Default for NoneAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl NoneAlgorithm {
    pub fn new() -> Self {
        NoneAlgorithm { metadata: None }
    }
}

impl NoneLike for NoneAlgorithm {
    fn jwt_alg_name() -> &'static str {
        "none"
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), JWTError> {
        self.metadata = Some(metadata);
        Ok(())
    }
}
