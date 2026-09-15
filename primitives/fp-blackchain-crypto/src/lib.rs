// fp-blackchain-crypto — Frontier bridge to blackchain-crypto-lib-rust.
//
// Architecture:
//
//   blackchain-crypto-lib-rust    ← ALL crypto lives here (api.rs, signing.rs, …)
//           ↓  path dep
//   fp-blackchain-crypto          ← this file: ~30 lines, pure delegation
//           ↓  workspace dep
//   pallet-ethereum               → calls verify_blackchain_tx(tx)
//   pallet-evm-precompile-simple  → calls verify_signature(hash, pub_key, sig)
//
// Public surface:
//   verify_blackchain_tx(tx)  — wraps blackchain_crypto_lib_rust::verify_transaction()
//   verify_signature(…)       — wraps BlackChainPublicKey verification for the precompile
//   BlackChainTransaction     — on-chain SCALE type (thin mirror of BlackChainTxType)
//   Re-exports: BlackChainPrivateKey, BlackChainPublicKey, BlackChainTxType, CryptoError

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

use scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;

// ---------------------------------------------------------------------------
// Re-export everything callers need from the library
// ---------------------------------------------------------------------------
pub use blackchain_crypto_lib_rust::{
    // Top-level API (the four clean functions)
    verify_transaction as verify_blackchain_tx,
    // Types
    crypto::{BlackChainPrivateKey, BlackChainPublicKey, COMPOSITE_PK_SIZE},
    error::CryptoError,
    transaction::types::BlackChainTxType,
};

// ---------------------------------------------------------------------------
// Size constants (mirror values from the library; hardcoded for no_std clarity)
// ---------------------------------------------------------------------------
/// FIPS 204 ML-DSA-87 signature (was CRYSTALS-Dilithium5 4595 before the 6b6ea51 migration).
pub const DIL_SIG_SIZE: usize = 4627;
/// P-521 ECDSA signature: fixed-width `r ‖ s` (66 bytes each), low-S canonical.
pub const P521_SIG_SIZE: usize = 132;
pub const ED448_SIG_SIZE: usize = 114;
/// Exact composite signature size: `ML-DSA-87 ‖ P-521 ‖ Ed448`. All three sub-signatures
/// are fixed-width, so a well-formed composite is exactly this length (4873). The
/// library rejects any other length (anti-malleability / anti-padding).
pub const COMPOSITE_SIG_SIZE: usize = DIL_SIG_SIZE + P521_SIG_SIZE + ED448_SIG_SIZE; // 4873
pub const TX_TYPE: u8 = 0x80;

// ---------------------------------------------------------------------------
#[cfg(feature = "std")]
pub fn verify_signature(
    tx_hash: &[u8; 32],
    chain_id: u64,
    pub_key_bytes: &[u8],
    pqc_sig: &[u8],
) -> Result<[u8; 20], CryptoError> {
    let address = blackchain_crypto_lib_rust::verify_signature(tx_hash, chain_id, pub_key_bytes, pqc_sig)?;
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(address.as_slice());
    Ok(address_bytes)
}


/// WASM stub — verification runs only in the native executor.
#[cfg(not(feature = "std"))]
pub fn verify_signature(
    _: &[u8; 32],
    _: u64,
    _: &[u8],
    _: &[u8],
) -> Result<[u8; 20], CryptoError> {
    Err(CryptoError::SignatureError(
        "verify_signature only available in native (std) context".into(),
    ))
}

// ---------------------------------------------------------------------------
// Generic composite-message verification (for the PQC-authenticated admin path).
//
// Unlike `verify_signature`, which verifies over a pre-computed transaction hash
// using the chain_id/address-bound entanglement nonce, this verifies over an
// ARBITRARY message using the generic `sign_message`/`verify_message` scheme
// (keccak256(message) internally, zeroed entanglement nonce). Domain separation
// and replay/chain binding for the admin path are carried INSIDE the message
// bytes (a domain tag, the chain_id and the admin nonce), not in the nonce.
//
// Returns the recovered signer address (keccak256(pub_key)[12..]) on success.
// ---------------------------------------------------------------------------
#[cfg(feature = "std")]
pub fn verify_message(
    message: &[u8],
    signature: &[u8],
    pub_key_bytes: &[u8],
) -> Result<[u8; 20], CryptoError> {
    let pub_key = BlackChainPublicKey::from_bytes(pub_key_bytes)?;
    if !pub_key.verify_message(message, signature)? {
        return Err(CryptoError::SignatureError(
            "composite message signature is invalid".into(),
        ));
    }
    let address = pub_key.derive_address();
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(address.as_slice());
    Ok(address_bytes)
}

/// WASM stub — verification runs only in the native executor.
#[cfg(not(feature = "std"))]
pub fn verify_message(
    _: &[u8],
    _: &[u8],
    _: &[u8],
) -> Result<[u8; 20], CryptoError> {
    Err(CryptoError::SignatureError(
        "verify_message only available in native (std) context".into(),
    ))
}

// ---------------------------------------------------------------------------
// BlackChainTransaction — SCALE-encoded on-chain type
//
// This is the Option-B wire format carrying native pqc_signature + pub_key
// fields.  pallet-ethereum stores and dispatches this type.
// On pallet-ethereum validation, the pallet calls:
//   Pallet::recover_blackchain_signer(&tx)
// which internally calls verify_transaction() from the library.
// ---------------------------------------------------------------------------
#[derive(Clone, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct BlackChainTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    /// EIP-1559 priority fee (U256 big-endian).
    pub max_priority_fee_per_gas: [u8; 32],
    /// EIP-1559 max fee (U256 big-endian).
    pub max_fee_per_gas: [u8; 32],
    pub gas_limit: u64,
    /// Recipient (20 bytes). Ignored when `is_create = true`.
    pub to: [u8; 20],
    pub is_create: bool,
    /// Value (U256 big-endian).
    pub value: [u8; 32],
    pub input: Vec<u8>,
    /// EIP-155 placeholder: chain_id * 2 + 35.
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// Composite PQC signature: [Dil5 ‖ P-521 ‖ Ed448].
    pub pqc_signature: Vec<u8>,
    /// Composite public key: [Dil5 pk ‖ P-521 pk ‖ Ed448 pk] (2782 B).
    pub pub_key: Vec<u8>,
}

impl core::fmt::Debug for BlackChainTransaction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlackChainTransaction")
            .field("chain_id", &self.chain_id)
            .field("nonce", &self.nonce)
            .field("gas_limit", &self.gas_limit)
            .field("is_create", &self.is_create)
            .field("pub_key_len", &self.pub_key.len())
            .field("pqc_sig_len", &self.pqc_signature.len())
            .finish_non_exhaustive()
    }
}
