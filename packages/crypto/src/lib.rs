#![doc = include_str!("../Readme.md")]

#[cfg(feature = "hash")]
mod hash;
#[cfg(feature = "rand")]
mod rng;
#[cfg(feature = "ecc-secp256k1")]
pub mod secp256k1;

#[cfg(feature = "hash")]
pub use hash::{sha_256, SHA256_HASH_SIZE};

#[cfg(feature = "rand")]
pub use rng::ContractPrng;

#[cfg(feature = "hkdf")]
pub mod hkdf;
#[cfg(feature = "hkdf")]
pub use crate::hkdf::*;
