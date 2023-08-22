use std::convert::TryFrom;

use base64ct::{Base64UrlUnpadded, Encoding};
use p384::ecdsa::{self, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _};
use p384::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p384::NonZeroScalar;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha384};

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct P384PublicKey(ecdsa::VerifyingKey);

impl AsRef<ecdsa::VerifyingKey> for P384PublicKey {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.0
    }
}

impl P384PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, JWTError> {
        let p384_pk =
            ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P384PublicKey(p384_pk))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, JWTError> {
        let p384_pk = ecdsa::VerifyingKey::from_public_key_der(der)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P384PublicKey(p384_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, JWTError> {
        let p384_pk = ecdsa::VerifyingKey::from_public_key_pem(pem)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P384PublicKey(p384_pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, JWTError> {
        let p384_pk = p384::PublicKey::from(self.0);
        Ok(p384_pk
            .to_public_key_der()
            .map_err(|_| JWTError::InvalidPublicKey)?
            .as_ref()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, JWTError> {
        let p384_pk = p384::PublicKey::from(self.0);
        p384_pk
            .to_public_key_pem(Default::default())
            .map_err(|_| JWTError::InvalidPublicKey)
    }
}

#[doc(hidden)]
pub struct P384KeyPair {
    p384_sk: ecdsa::SigningKey,
    metadata: Option<KeyMetadata>,
}

impl AsRef<ecdsa::SigningKey> for P384KeyPair {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.p384_sk
    }
}

impl P384KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, JWTError> {
        let p384_sk =
            ecdsa::SigningKey::from_bytes(raw.into()).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P384KeyPair {
            p384_sk,
            metadata: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, JWTError> {
        let p384_sk =
            ecdsa::SigningKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P384KeyPair {
            p384_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, JWTError> {
        let p384_sk =
            ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P384KeyPair {
            p384_sk,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.p384_sk.to_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, JWTError> {
        let scalar = NonZeroScalar::from_repr(self.p384_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair);
        }
        let p384_sk =
            p384::SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p384_sk
            .to_pkcs8_der()
            .map_err(|_| JWTError::InvalidKeyPair)?
            .as_bytes()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, JWTError> {
        let scalar = NonZeroScalar::from_repr(self.p384_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair);
        }
        let p384_sk =
            p384::SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p384_sk
            .to_pkcs8_pem(Default::default())
            .map_err(|_| JWTError::InvalidKeyPair)?
            .to_string())
    }

    pub fn public_key(&self) -> P384PublicKey {
        let p384_sk = self.p384_sk.verifying_key();
        P384PublicKey(*p384_sk)
    }

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let p384_sk = ecdsa::SigningKey::random(&mut rng);
        P384KeyPair {
            p384_sk,
            metadata: None,
        }
    }
}

pub trait ECDSAP384KeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &P384KeyPair;
    fn key_id(&self) -> &Option<String>;
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), JWTError>;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, JWTError> {
        let jwt_header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone())
            .with_metadata(self.metadata());
        Token::build(&jwt_header, claims, |authenticated| {
            let mut digest = Sha384::new();
            digest.update(authenticated.as_bytes());
            let mut rng = rand::thread_rng();
            let signature: ecdsa::Signature = self
                .key_pair()
                .as_ref()
                .sign_digest_with_rng(&mut rng, digest);
            Ok(signature.to_vec())
        })
    }
}

pub trait ECDSAP384PublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &P384PublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);

    fn verify_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, JWTError> {
        Token::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                let mut digest = Sha384::new();
                digest.update(authenticated.as_bytes());
                self.public_key()
                    .as_ref()
                    .verify_digest(digest, &ecdsa_signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }

    fn create_key_id(&mut self) -> Result<String, JWTError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.public_key().to_bytes());
        let key_id = Base64UrlUnpadded::encode_string(&hasher.finalize());
        self.set_key_id(key_id.clone());
        Ok(key_id)
    }
}

pub struct ES384KeyPair {
    key_pair: P384KeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ES384PublicKey {
    pk: P384PublicKey,
    key_id: Option<String>,
}

impl ECDSAP384KeyPairLike for ES384KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ES384"
    }

    fn key_pair(&self) -> &P384KeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key_pair.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), JWTError> {
        self.key_pair.metadata = Some(metadata);
        Ok(())
    }
}

impl ES384KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, JWTError> {
        Ok(ES384KeyPair {
            key_pair: P384KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, JWTError> {
        Ok(ES384KeyPair {
            key_pair: P384KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, JWTError> {
        Ok(ES384KeyPair {
            key_pair: P384KeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, JWTError> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, JWTError> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> ES384PublicKey {
        ES384PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        ES384KeyPair {
            key_pair: P384KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl ECDSAP384PublicKeyLike for ES384PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ES384"
    }

    fn public_key(&self) -> &P384PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl ES384PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, JWTError> {
        Ok(ES384PublicKey {
            pk: P384PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, JWTError> {
        Ok(ES384PublicKey {
            pk: P384PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, JWTError> {
        Ok(ES384PublicKey {
            pk: P384PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, JWTError> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, JWTError> {
        self.pk.to_pem()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}
