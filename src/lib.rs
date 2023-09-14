#![deny(unused_crate_dependencies)]
#![no_std]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::{string::String, vec::Vec, fmt::{Display, Formatter, Result as FmtResult}};

use parity_scale_codec::{Decode, Encode};
use sp_core::{ByteArray, H256};

#[derive(Clone, Copy, Debug, Decode, Encode, Eq, PartialEq)]
pub enum Encryption {
    #[codec(index = 0)]
    Ed25519,

    #[codec(index = 1)]
    Sr25519,

    #[codec(index = 2)]
    Ecdsa,
}

impl Encryption {
    pub fn key_length(&self) -> usize {
        match &self {
            Encryption::Ed25519 => sp_core::ed25519::Public::LEN,
            Encryption::Sr25519 => sp_core::sr25519::Public::LEN,
            Encryption::Ecdsa => sp_core::ecdsa::Public::LEN,
        }
    }
    pub fn signature_length(&self) -> usize {
        match &self {
            Encryption::Ed25519 => 64,
            Encryption::Sr25519 => 64,
            Encryption::Ecdsa => 65,
        }
    }
}

impl Display for Encryption {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let text = match &self {
            Self::Ed25519 => "Ed25519",
            Self::Sr25519 => "Sr25519",
            Self::Ecdsa => "Ecdsa",
        };
        write!(f, "{}", text)
   }
}

#[derive(Debug, Decode, Encode)]
#[repr(C)]
pub struct TransferData {
    pub encoded_data: Vec<u8>,
    pub companion_signature: Vec<u8>,
    pub companion_public_key: Vec<u8>,
}

#[derive(Debug, Decode, Encode, Eq, PartialEq)]
pub enum TransmittableContent {
    #[codec(index = 0)]
    KampelaStop,

    #[codec(index = 1)]
    Bytes(Bytes),

    #[codec(index = 2)]
    Derivation(DerivationInfo),

    #[codec(index = 3)]
    SignableTransaction(Transaction),
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub enum MultiSigner {
    #[codec(index = 0)]
    Ed25519(sp_core::ed25519::Public),

    #[codec(index = 1)]
    Sr25519(sp_core::sr25519::Public),

    #[codec(index = 2)]
    Ecdsa(sp_core::ecdsa::Public),
}

#[derive(Debug, Decode, Encode, Eq, PartialEq)]
#[repr(C)]
pub struct Bytes {
    pub bytes_uncut: Vec<u8>,
    pub signer: MultiSigner,
}

#[derive(Debug, Decode, Encode, Eq, PartialEq)]
#[repr(C)]
pub struct Transaction {
    pub genesis_hash: H256,
    pub encoded_short_meta: Vec<u8>,
    pub encoded_signable_transaction: Vec<u8>,
    pub signer: MultiSigner,
}

#[derive(Debug, Decode, Encode, Eq, PartialEq)]
#[repr(C)]
pub struct DerivationInfo {
    pub cut_path: String,
    pub has_pwd: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_encryption() {
        assert_eq!(
            Encryption::decode(&mut [0].as_slice()).unwrap(),
            Encryption::Ed25519
        );
        assert_eq!(
            Encryption::decode(&mut [1].as_slice()).unwrap(),
            Encryption::Sr25519
        );
        assert_eq!(
            Encryption::decode(&mut [2].as_slice()).unwrap(),
            Encryption::Ecdsa
        );
        assert!(Encryption::decode(&mut [3].as_slice()).is_err());
    }
}
