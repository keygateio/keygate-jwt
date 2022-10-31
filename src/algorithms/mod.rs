#[cfg(feature = "eddsa")]
mod eddsa;
#[cfg(feature = "eddsa")]
pub use self::eddsa::*;

#[cfg(feature = "ecdsa")]
mod es256;
#[cfg(feature = "ecdsa")]
mod es256k;
#[cfg(feature = "ecdsa")]
mod es384;

#[cfg(feature = "ecdsa")]
pub use self::es256::*;
#[cfg(feature = "ecdsa")]
pub use self::es256k::*;
#[cfg(feature = "ecdsa")]
pub use self::es384::*;

#[cfg(feature = "none")]
mod none;
#[cfg(feature = "none")]
pub use self::none::*;
