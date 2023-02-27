[![GitHub CI](https://github.com/keygateio/keygate-jwt/workflows/Rust/badge.svg)](https://github.com/keygateio/keygate-jwt/actions)
[![Docs.rs](https://docs.rs/keygate-jwt/badge.svg)](https://docs.rs/keygate-jwt/)
[![crates.io](https://img.shields.io/crates/v/keygate-jwt.svg)](https://crates.io/crates/keygate-jwt)

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [keygate-jwt](#keygate-jwt)
  - [Usage](#usage)
  - [Signatures](#signatures)
    - [Key pairs and tokens creation](#key-pairs-and-tokens-creation)
      - [ES256](#es256)
      - [ES384](#es384)
  - [Advanced usage](#advanced-usage)
    - [Custom claims](#custom-claims)
    - [Peeking at metadata before verification](#peeking-at-metadata-before-verification)
    - [Mitigations against replay attacks](#mitigations-against-replay-attacks)
  - [Why yet another JWT crate](#why-yet-another-jwt-crate)
  - [Credits](#credits)

<!-- /code_chunk_output -->

# keygate-jwt

A new JWT (JSON Web Tokens) implementation for Rust that focuses on simplicity, while avoiding common JWT security pitfalls.

`keygate-jwt` is opinionated and only supports secure signature algorithms:

| JWT algorithm name | Feature | Description                    |
| ------------------ | ------- | ------------------------------ |
| `EdDSA`            | `eddsa` | Ed25519 (Recommended)          |
| `ES256`            | `ecdsa` | ECDSA over p256 / SHA-256      |
| `ES384`            | `ecdsa` | ECDSA over p384 / SHA-384      |
| `ES256K`           | `ecdsa` | ECDSA over secp256k1 / SHA-256 |

Whenever possible, you should use `EdDSA`, however not all JWT libraries support it yet so `ecdsa` is also supported.

`keygate-jwt` uses only pure Rust implementations, and can be compiled out of the box to WebAssembly/WASI.

Important: JWT's purpose is to verify that data has been created by a party knowing a secret key. It does not provide any kind of confidentiality: JWT data is simply encoded as BASE64, and is not encrypted.

## Usage

`cargo.toml`:

```toml
[dependencies]
keygate-jwt = "1.0"
```

Errors are returned as `keygate-jwt::Error` values

## Signatures

A signature requires a key pair: a secret key used to create tokens, and a public key, that can only verify them.

Always use a signature scheme if both parties do not ultimately trust each other, such as tokens exchanged between clients and API providers.

### Key pairs and tokens creation

Key creation:

#### ES256

```rust
use keygate_jwt::prelude::*;

// create a new key pair for the `ES256` JWT algorithm
let key_pair = ES256KeyPair::generate();

// a public key can be extracted from a key pair:
let public_key = key_pair.public_key();
```

#### ES384

```rust
use keygate_jwt::prelude::*;

// create a new key pair for the `ES384` JWT algorithm
let key_pair = ES384KeyPair::generate();

// a public key can be extracted from a key pair:
let public_key = key_pair.public_key();
```

Keys can be exported as bytes for later reuse, and imported from bytes or, for RSA, from individual parameters, DER-encoded data or PEM-encoded data.

RSA key pair creation, using OpenSSL and PEM importation of the secret key:

```sh
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

```rust
let key_pair = RS384KeyPair::from_pem(private_pem_file_content)?;
let public_key = RS384PublicKey::from_pem(public_pem_file_content)?;
```

Token creation and verification work the same way as with `HS*` algorithms, except that tokens are created with a key pair, and verified using the corresponding public key.

Token creation:

```rust
/// create claims valid for 2 hours
let claims = Claims::create(Duration::from_hours(2));
let token = key_pair.sign(claims)?;
```

Token verification:

```rust
let claims = public_key.verify_token::<NoCustomClaims>(&token, None)?;
```

Available verification options are identical to the ones used with symmetric algorithms.

## Advanced usage

### Custom claims

Claim objects support all the standard claims by default, and they can be set directly or via convenient helpers:

```rust
let claims = Claims::create(Duration::from_hours(2)).
    with_issuer("Example issuer").with_subject("Example subject");
```

But application-defined claims can also be defined. These simply have to be present in a serializable type (this requires the `serde` crate):

```rust
#[derive(Serialize, Deserialize)]
struct MyAdditionalData {
   user_is_admin: bool,
   user_country: String,
}
let my_additional_data = MyAdditionalData {
   user_is_admin: false,
   user_country: "FR".to_string(),
};
```

Claim creation with custom data:

```rust
let claims = Claims::with_custom_claims(my_additional_data, Duration::from_secs(30));
```

Claim verification with custom data. Note the presence of the custom data type:

```rust
let claims = public_key.verify_token::<MyAdditionalData>(&token, None)?;
let user_is_admin = claims.custom.user_is_admin;
```

### Peeking at metadata before verification

Properties such as the key identifier can be useful prior to tag or signature verification in order to pick the right key out of a set.

```rust
let metadata = Token::decode_metadata(&token)?;
let key_id = metadata.key_id();
let algorithm = metadata.algorithm();
// all other standard properties are also accessible
```

**IMPORTANT:** neither the key ID nor the algorithm can be trusted. This is an unfixable design flaw of the JWT standard.

As a result, `algorithm` should be used only for debugging purposes, and never to select a key type.
Similarly, `key_id` should be used only to select a key in a set of keys made for the same algorithm.

### Mitigations against replay attacks

`keygate-jwt` includes mechanisms to mitigate replay attacks:

- Nonces can be attached to new tokens using the `with_nonce()` claim function. The verification procedure can later reject any token that doesn't include the expected nonce (`required_nonce` verification option).
- The verification procedure can reject tokens created too long ago, no matter what their expiration date is. This prevents tokens from malicious (or compromised) signers from being used for too long.
- The verification procedure can reject tokens created before a date. For a given user, the date of the last successful authentication can be stored in a database, and used later along with this option to reject older (replayed) tokens.

## Why yet another JWT crate

There are already several JWT crates for Rust, but none of them satisfied our needs:

- no insecure algorithms (such as `RSA` or `HS256`) and hash functions (such as `SHA1`) are supported
- minimal, rust-only dependencies

## Credits

This crate is based on the [jwt-simple](https://github.com/jedisct1/rust-jwt-simple) project by Frank Denis. Notable changes are the introduction of cargo feature flags and unneeded dependencies, and the removal of support for insecure algorithms. [1](https://github.com/jedisct1/rust-jwt-simple/issues/72)
