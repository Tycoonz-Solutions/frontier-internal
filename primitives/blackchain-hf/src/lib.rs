// primitives/blackchain-hf/src/lib.rs
//
// Substrate host function: `blackchain_crypto::verify_pqc_transaction`
//
// ## Architecture
//
// This crate exposes a Substrate host function for full PQC signature
// verification (Dilithium5 + P-521 + Ed448) callable from the WASM runtime.
//
// ## RIType wrapper rules (stable2512)
//
// The `#[runtime_interface]` macro in polkadot-sdk stable2512 requires explicit
// `pass_by` wrapper types — bare `Vec<u8>`, `&[u8]`, `Option<_>` are NOT RIType:
//
//   Input  Vec<u8>  → PassFatPointerAndRead<Vec<u8>>
//   Output Vec<u8>  → AllocateAndReturnFatPointer<Vec<u8>>
//
// ## Wire protocol
//
// The entire `BlackChainTransaction` is SCALE-encoded into one `Vec<u8>` on
// the WASM side. The host side SCALE-decodes it, reconstructs `BlackChainTxType`,
// computes the RLP signature hash (std-only via alloy_rlp), and runs the full
// cryptographic verification.
//
// Return value: `Vec<u8>`
//   - exactly 20 bytes  → verified sender address
//   - empty (len == 0)  → verification failed

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

use sp_runtime_interface::{
	pass_by::{AllocateAndReturnFatPointer, PassFatPointerAndRead},
	runtime_interface,
};

/// The host-function interface callable from the WASM runtime.
#[runtime_interface]
pub trait BlackchainCrypto {
	/// Verify a SCALE-encoded `BlackChainTransaction` and return the sender.
	///
	/// # Input
	/// `encoded_tx` — SCALE bytes of `fp_blackchain_crypto::BlackChainTransaction`.
	///
	/// # Output
	/// - 20-byte `Vec<u8>` — verified sender H160 address.
	/// - Empty `Vec<u8>`  — verification failed (bad sig, decode error, etc.).
	fn verify_pqc_transaction(
		encoded_tx: PassFatPointerAndRead<Vec<u8>>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};
		use fp_blackchain_crypto::{verify_blackchain_tx, BlackChainTransaction, BlackChainTxType};
		use scale_codec::Decode;

		// SCALE-decode the BlackChainTransaction
		let tx = match BlackChainTransaction::decode(&mut encoded_tx.as_slice()) {
			Ok(t) => t,
			Err(e) => {
				log::warn!(
					target: "blackchain_crypto",
					"[host-fn] SCALE decode failed: {e:?}"
				);
				return Vec::new();
			}
		};

		// Reconstruct the library type for verification
		let lib_tx = BlackChainTxType {
			chain_id: tx.chain_id,
			nonce: tx.nonce,
			max_priority_fee_per_gas: AlloyU256::from_be_bytes(tx.max_priority_fee_per_gas),
			max_fee_per_gas: AlloyU256::from_be_bytes(tx.max_fee_per_gas),
			gas_limit: tx.gas_limit,
			to: if tx.is_create {
				None
			} else {
				Some(AlloyAddress::from_slice(&tx.to))
			},
			value: AlloyU256::from_be_bytes(tx.value),
			data: AlloyBytes::from(tx.input),
			v: Some(AlloyU256::from(tx.v)),
			r: Some(AlloyU256::ZERO),
			s: Some(AlloyU256::ZERO),
			pqc_signature: Some(AlloyBytes::from(tx.pqc_signature)),
			pub_key: Some(AlloyBytes::from(tx.pub_key)),
		};

		match verify_blackchain_tx(&lib_tx) {
			Ok(addr) => {
				log::info!(
					target: "blackchain_crypto",
					"[host-fn] PQC signature VALID — sender: {addr:?}",
				);
				addr.as_slice().to_vec()
			}
			Err(e) => {
				log::warn!(
					target: "blackchain_crypto",
					"[host-fn] PQC signature INVALID — {e:?}",
				);
				Vec::new()
			}
		}
	}

	/// Verify a standalone composite PQC signature over a 32-byte hash and return
	/// the recovered sender address.
	///
	/// This is the primitive used by the EVM `BlackChainVerify` precompile so that
	/// smart contracts can verify Dilithium5 + P-521 + Ed448 signatures on-chain.
	/// Unlike `verify_pqc_transaction`, it does not decode a full transaction — the
	/// caller supplies the pre-computed signing hash directly.
	///
	/// # Input
	/// - `hash`     — the 32-byte message/transaction hash that was signed.
	/// - `chain_id` — chain id used in the entanglement-nonce domain separation.
	/// - `pub_key`  — the 2782-byte composite public key.
	/// - `pqc_sig`  — the composite signature `[Dil5 ‖ P-521 ‖ Ed448]`.
	///
	/// # Output
	/// - 20-byte `Vec<u8>` — verified sender H160 address.
	/// - Empty `Vec<u8>`  — verification failed (bad length, bad sig, etc.).
	fn verify_pqc_signature(
		hash: PassFatPointerAndRead<Vec<u8>>,
		chain_id: u64,
		pub_key: PassFatPointerAndRead<Vec<u8>>,
		pqc_sig: PassFatPointerAndRead<Vec<u8>>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use fp_blackchain_crypto::verify_signature;

		if hash.len() != 32 {
			log::warn!(
				target: "blackchain_crypto",
				"[host-fn] verify_pqc_signature: hash must be 32 bytes, got {}",
				hash.len(),
			);
			return Vec::new();
		}
		let mut hash_arr = [0u8; 32];
		hash_arr.copy_from_slice(&hash);

		match verify_signature(&hash_arr, chain_id, &pub_key, &pqc_sig) {
			Ok(addr) => addr.to_vec(),
			Err(e) => {
				log::warn!(
					target: "blackchain_crypto",
					"[host-fn] verify_pqc_signature INVALID — {e:?}",
				);
				Vec::new()
			}
		}
	}

	/// Verify a composite PQC signature over an ARBITRARY message (generic
	/// `sign_message`/`verify_message` scheme) and return the recovered signer.
	///
	/// Used by the PQC-authenticated admin path (`pallet-blackchain-sudo`): the
	/// message is a domain-separated payload binding a chain id, an admin nonce
	/// and the SCALE-encoded privileged call, so replay and cross-chain use are
	/// prevented by the message content rather than by the entanglement nonce.
	///
	/// # Input
	/// - `message`   — the exact signed payload bytes.
	/// - `signature` — the composite signature `[ML-DSA-87 ‖ P-521 ‖ Ed448]` (4873 B).
	/// - `pub_key`   — the 2782-byte composite public key.
	///
	/// # Output
	/// - 20-byte `Vec<u8>` — verified signer H160 address (keccak(pub_key)[12..]).
	/// - Empty `Vec<u8>`  — verification failed (bad length, bad sig, etc.).
	fn verify_pqc_message(
		message: PassFatPointerAndRead<Vec<u8>>,
		signature: PassFatPointerAndRead<Vec<u8>>,
		pub_key: PassFatPointerAndRead<Vec<u8>>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use fp_blackchain_crypto::verify_message;

		match verify_message(&message, &signature, &pub_key) {
			Ok(addr) => addr.to_vec(),
			Err(e) => {
				log::warn!(
					target: "blackchain_crypto",
					"[host-fn] verify_pqc_message INVALID — {e:?}",
				);
				Vec::new()
			}
		}
	}
}
