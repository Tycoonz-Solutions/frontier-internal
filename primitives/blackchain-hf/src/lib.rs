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

/// One item in a mixed PQC verification batch.
///
/// A block can carry two kinds of PQC-authenticated transaction that verify with
/// DIFFERENT schemes, so a single batch must tag each item with which scheme to
/// use:
///
/// * [`Self::Transaction`] — the EVM path (`transact_blackchain`): a SCALE-encoded
///   `BlackChainTransaction`. Verified with the chain_id-bound entanglement scheme
///   (`verify_blackchain_tx`), computing the signing hash from the tx fields.
/// * [`Self::Message`] — the generic message path (e.g. native
///   `transfer_blackchain`, PQC sudo): raw signed `message` bytes + composite
///   `signature` + composite `pub_key`. Verified with the zeroed-entanglement
///   `verify_message` scheme (domain separation lives inside `message`).
///
/// This type is `no_std`-safe and only SCALE-encoded — it crosses the WASM→host
/// boundary; the runtime builds the `Vec<PqcBatchItem>`, the host verifies it.
#[derive(Clone, PartialEq, Eq, scale_codec::Encode, scale_codec::Decode)]
pub enum PqcBatchItem {
	/// EVM path: SCALE bytes of a `BlackChainTransaction`.
	Transaction(Vec<u8>),
	/// Message path: `(signed message, composite signature, composite pub key)`.
	Message {
		message: Vec<u8>,
		signature: Vec<u8>,
		pub_key: Vec<u8>,
	},
}

/// Native-only core of single-transaction verification.
///
/// SCALE-decodes one `BlackChainTransaction`, reconstructs the library type and
/// runs the full composite PQC verification. Returns the 20-byte sender address
/// on success, or an empty `Vec` on any failure (decode error or bad signature).
///
/// Both `verify_pqc_transaction` and `verify_pqc_transaction_batch` call this so
/// that the serial and parallel paths are bit-for-bit identical per item.
///
/// Public (std-only) so native tooling — e.g. the `pqc_batch` example — can
/// drive the exact verification path the runtime uses, with no WASM/runtime
/// externalities context.
#[cfg(feature = "std")]
pub fn verify_one_tx(encoded_tx: &[u8]) -> Vec<u8> {
	use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};
	use fp_blackchain_crypto::{verify_blackchain_tx, BlackChainTransaction, BlackChainTxType};
	use scale_codec::Decode;

	// SCALE-decode the BlackChainTransaction
	let tx = match BlackChainTransaction::decode(&mut &encoded_tx[..]) {
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

/// Native-only core of batch verification.
///
/// SCALE-decodes the outer `Vec<Vec<u8>>` envelope (a list of encoded
/// `BlackChainTransaction`s) and verifies every item in parallel via rayon,
/// returning a flat `20 * N`-byte buffer. Chunk `i` is the 20-byte verified
/// sender of item `i`, or 20 zero bytes if item `i` failed. Returns an empty
/// `Vec` if the envelope itself fails to decode.
///
/// `verify_pqc_transaction_batch` is a thin wrapper over this; keeping the logic
/// in a plain function lets unit tests and native tooling (the `pqc_batch`
/// example) exercise the exact code path without a runtime-externalities context.
#[cfg(feature = "std")]
pub fn verify_batch_core(encoded_batch: &[u8]) -> Vec<u8> {
	use rayon::prelude::*;
	use scale_codec::Decode;

	// SCALE-decode the outer envelope: a list of encoded transactions.
	let items = match Vec::<Vec<u8>>::decode(&mut &encoded_batch[..]) {
		Ok(v) => v,
		Err(e) => {
			log::warn!(
				target: "blackchain_crypto",
				"[host-fn] batch envelope SCALE decode failed: {e:?}"
			);
			return Vec::new();
		}
	};

	log::debug!(
		target: "blackchain_crypto",
		"[host-fn] verifying PQC batch of {} transaction(s)",
		items.len(),
	);

	// Verify each item in parallel. `map` over a parallel iterator preserves
	// input order, so `results[i]` corresponds to `items[i]`.
	let results: Vec<Vec<u8>> = items
		.par_iter()
		.map(|encoded_tx| {
			let out = verify_one_tx_cached(encoded_tx);
			// Normalise to a fixed 20-byte chunk: success -> address,
			// failure -> all-zero sentinel.
			if out.len() == 20 {
				out
			} else {
				alloc::vec![0u8; 20]
			}
		})
		.collect();

	// Flatten into a single 20*N byte buffer for the WASM boundary.
	let mut flat = Vec::with_capacity(results.len() * 20);
	for chunk in results {
		flat.extend_from_slice(&chunk);
	}
	flat
}

/// Native-only core of single generic-message verification.
///
/// Verifies a composite PQC signature over arbitrary `message` bytes with the
/// generic `verify_message` scheme (zeroed entanglement; domain separation is
/// inside `message`) and returns the 20-byte signer, or an empty `Vec` on any
/// failure. This is the per-item primitive for the message path of a mixed batch
/// and mirrors the body of the `verify_pqc_message` host function.
#[cfg(feature = "std")]
pub fn verify_one_message(message: &[u8], signature: &[u8], pub_key: &[u8]) -> Vec<u8> {
	match fp_blackchain_crypto::verify_message(message, signature, pub_key) {
		Ok(addr) => addr.to_vec(),
		Err(e) => {
			log::warn!(
				target: "blackchain_crypto",
				"[host-fn] message signature INVALID — {e:?}",
			);
			Vec::new()
		}
	}
}

/// Native-only core of MIXED batch verification.
///
/// SCALE-decodes a `Vec<PqcBatchItem>` and verifies every item in parallel via
/// rayon, routing each to the scheme its tag selects: `Transaction` items go
/// through [`verify_one_tx`] (EVM, chain_id-bound) and `Message` items through
/// [`verify_one_message`] (generic message). Returns a flat `20 * N`-byte buffer
/// where chunk `i` is the verified signer of item `i`, or 20 zero bytes if item
/// `i` failed. Returns an empty `Vec` if the envelope itself fails to decode.
///
/// This lets a single parallel pass verify a whole block's PQC transactions even
/// when they mix the native-transfer and EVM paths. `verify_pqc_batch` is a thin
/// wrapper over this; keeping the logic here lets unit tests exercise it without
/// a runtime-externalities context.
#[cfg(feature = "std")]
pub fn verify_mixed_batch_core(encoded_batch: &[u8]) -> Vec<u8> {
	use rayon::prelude::*;
	use scale_codec::Decode;

	let items = match Vec::<PqcBatchItem>::decode(&mut &encoded_batch[..]) {
		Ok(v) => v,
		Err(e) => {
			log::warn!(
				target: "blackchain_crypto",
				"[host-fn] mixed batch envelope SCALE decode failed: {e:?}"
			);
			return Vec::new();
		}
	};

	log::debug!(
		target: "blackchain_crypto",
		"[host-fn] verifying mixed PQC batch of {} item(s)",
		items.len(),
	);

	// Verify each item in parallel; `map` preserves input order so `results[i]`
	// corresponds to `items[i]`.
	let results: Vec<Vec<u8>> = items
		.par_iter()
		.map(|item| {
			let out = match item {
				PqcBatchItem::Transaction(encoded_tx) => verify_one_tx_cached(encoded_tx),
				PqcBatchItem::Message {
					message,
					signature,
					pub_key,
				} => verify_one_message_cached(message, signature, pub_key),
			};
			if out.len() == 20 {
				out
			} else {
				alloc::vec![0u8; 20]
			}
		})
		.collect();

	let mut flat = Vec::with_capacity(results.len() * 20);
	for chunk in results {
		flat.extend_from_slice(&chunk);
	}
	flat
}

/// Native-only memoization of composite PQC verification results.
///
/// Verification is a PURE function of its input bytes — it reads NO chain state
/// (nonce/balance checks happen later in the pallet, not here). Memoizing a pure
/// function can only change speed, never the result, so every node still computes
/// identical state (consensus-safe), and a result stays valid for that input
/// forever (chain_id is fixed). Only *successful* verifications are cached. The
/// key is a keccak256 over a one-byte scheme tag plus the exact, length-delimited
/// inputs, so distinct inputs — and the two schemes — never collide. A
/// two-generation bounded map caps memory (~2 × `CAP` entries).
///
/// This removes the pool-admission → block-execution double-verify: a signature
/// checked once in the mempool is a cache hit when its block is imported.
#[cfg(feature = "std")]
mod verify_cache {
	use alloy_primitives::keccak256;
	use core::sync::atomic::{AtomicU64, Ordering};
	use std::collections::HashMap;
	use std::sync::{Mutex, OnceLock};

	/// Max live entries per generation; total memory is bounded at ~2× this.
	const CAP: usize = 16_384;

	/// Process-wide lookup counters, so an operator can see that pre-warmed
	/// signatures are served from cache at block-execution time (vs re-verified).
	static HITS: AtomicU64 = AtomicU64::new(0);
	static MISSES: AtomicU64 = AtomicU64::new(0);

	struct TwoGen {
		cur: HashMap<[u8; 32], [u8; 20]>,
		prev: HashMap<[u8; 32], [u8; 20]>,
	}

	fn store() -> &'static Mutex<TwoGen> {
		static S: OnceLock<Mutex<TwoGen>> = OnceLock::new();
		S.get_or_init(|| {
			Mutex::new(TwoGen {
				cur: HashMap::new(),
				prev: HashMap::new(),
			})
		})
	}

	/// Cache key for the EVM transaction path: `keccak256(0x01 ‖ encoded_tx)`.
	pub(super) fn tx_key(encoded_tx: &[u8]) -> [u8; 32] {
		let mut buf = alloc::vec::Vec::with_capacity(1 + encoded_tx.len());
		buf.push(0x01);
		buf.extend_from_slice(encoded_tx);
		keccak256(&buf).0
	}

	/// Cache key for the generic message path:
	/// `keccak256(0x02 ‖ len(m)‖m ‖ len(s)‖s ‖ len(pk)‖pk)` (length-delimited so
	/// no concatenation of different components can ever collide).
	pub(super) fn msg_key(message: &[u8], signature: &[u8], pub_key: &[u8]) -> [u8; 32] {
		let mut buf = alloc::vec::Vec::with_capacity(
			1 + 24 + message.len() + signature.len() + pub_key.len(),
		);
		buf.push(0x02);
		for part in [message, signature, pub_key] {
			buf.extend_from_slice(&(part.len() as u64).to_le_bytes());
			buf.extend_from_slice(part);
		}
		keccak256(&buf).0
	}

	pub(super) fn get(key: &[u8; 32]) -> Option<[u8; 20]> {
		let g = store().lock().expect("verify cache mutex poisoned");
		let found = g.cur.get(key).or_else(|| g.prev.get(key)).copied();
		if found.is_some() {
			HITS.fetch_add(1, Ordering::Relaxed);
		} else {
			MISSES.fetch_add(1, Ordering::Relaxed);
		}
		found
	}

	/// Cumulative `(hits, misses)` across every cache lookup in this process.
	pub(super) fn stats() -> (u64, u64) {
		(HITS.load(Ordering::Relaxed), MISSES.load(Ordering::Relaxed))
	}

	pub(super) fn put(key: [u8; 32], signer: [u8; 20]) {
		let mut g = store().lock().expect("verify cache mutex poisoned");
		if g.cur.len() >= CAP {
			// Rotate: retire the current generation to `prev`, start a fresh one.
			let full = core::mem::take(&mut g.cur);
			g.prev = full;
		}
		g.cur.insert(key, signer);
	}

	#[cfg(test)]
	pub(super) fn clear() {
		let mut g = store().lock().expect("verify cache mutex poisoned");
		g.cur.clear();
		g.prev.clear();
	}
}

/// Cumulative verify-cache `(hits, misses)` for this process. A hit means a
/// signature's verification result was served from the cache instead of being
/// recomputed — e.g. a block's signatures warmed by the import pre-pass are hits
/// when the runtime then executes that block. Monotonically non-decreasing.
#[cfg(feature = "std")]
pub fn cache_stats() -> (u64, u64) {
	verify_cache::stats()
}

/// Cached wrapper over [`verify_one_tx`] (EVM path). Returns the cached signer on
/// a hit, otherwise verifies and caches a success. Used by the production host-fn
/// path; the uncached [`verify_one_tx`] stays available for tooling/measurement.
#[cfg(feature = "std")]
pub fn verify_one_tx_cached(encoded_tx: &[u8]) -> Vec<u8> {
	let key = verify_cache::tx_key(encoded_tx);
	if let Some(signer) = verify_cache::get(&key) {
		return signer.to_vec();
	}
	let out = verify_one_tx(encoded_tx);
	if out.len() == 20 {
		let mut a = [0u8; 20];
		a.copy_from_slice(&out);
		verify_cache::put(key, a);
	}
	out
}

/// Cached wrapper over [`verify_one_message`] (generic message path).
#[cfg(feature = "std")]
pub fn verify_one_message_cached(message: &[u8], signature: &[u8], pub_key: &[u8]) -> Vec<u8> {
	let key = verify_cache::msg_key(message, signature, pub_key);
	if let Some(signer) = verify_cache::get(&key) {
		return signer.to_vec();
	}
	let out = verify_one_message(message, signature, pub_key);
	if out.len() == 20 {
		let mut a = [0u8; 20];
		a.copy_from_slice(&out);
		verify_cache::put(key, a);
	}
	out
}

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
		verify_one_tx_cached(encoded_tx.as_slice())
	}

	/// Verify a batch of SCALE-encoded `BlackChainTransaction`s in parallel and
	/// return an index-aligned block of per-transaction results.
	///
	/// Each composite verification costs ~1.6 ms, so a full block of PQC
	/// transactions is dominated by signature checking. This host function fans
	/// the per-transaction work out across a rayon thread pool on the native side
	/// while the WASM runtime pays for a single host-call boundary crossing.
	///
	/// # Input
	/// `encoded_batch` — SCALE bytes of `Vec<Vec<u8>>`, i.e. a list where each
	/// element is itself the SCALE encoding of one `BlackChainTransaction` (the
	/// exact same bytes `verify_pqc_transaction` accepts).
	///
	/// # Output
	/// A flat `Vec<u8>` of length `20 * N`, where `N` is the number of input
	/// transactions. Chunk `i` (`[20*i .. 20*i+20]`) is:
	/// - the verified 20-byte sender address for transaction `i`, or
	/// - 20 zero bytes if transaction `i` failed to verify (bad sig / decode).
	///
	/// Results are **index-aligned and deterministic**: `rayon` parallelises
	/// execution but preserves input order, and each item is verified in
	/// isolation, so the output is identical to verifying every item serially
	/// with `verify_pqc_transaction`. On a decode failure of the outer
	/// `Vec<Vec<u8>>` envelope, an empty `Vec` is returned.
	fn verify_pqc_transaction_batch(
		encoded_batch: PassFatPointerAndRead<Vec<u8>>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		verify_batch_core(encoded_batch.as_slice())
	}

	/// Verify a MIXED batch of PQC-authenticated items in parallel — EVM
		/// transactions and generic-message transactions (e.g. native transfers)
		/// together — and return an index-aligned block of per-item results.
		///
		/// This is the generalised form of `verify_pqc_transaction_batch`: a block
		/// can contain both `transact_blackchain` (EVM, chain_id-bound scheme) and
		/// `transfer_blackchain` (native, generic-message scheme), which verify with
		/// different functions. Tagging each item with `PqcBatchItem` lets one
		/// parallel pass verify the whole block regardless of the mix.
		///
		/// # Input
		/// `encoded_batch` — SCALE bytes of `Vec<PqcBatchItem>`. Each item is either
		/// `Transaction(encoded_tx)` (same bytes `verify_pqc_transaction` accepts) or
		/// `Message { message, signature, pub_key }` (same inputs `verify_pqc_message`
		/// accepts).
		///
		/// # Output
		/// A flat `Vec<u8>` of length `20 * N`. Chunk `i` is the verified 20-byte
		/// signer of item `i`, or 20 zero bytes if item `i` failed. Index-aligned and
		/// deterministic. An empty `Vec` means the envelope failed to decode.
		fn verify_pqc_batch(
			encoded_batch: PassFatPointerAndRead<Vec<u8>>,
		) -> AllocateAndReturnFatPointer<Vec<u8>> {
			verify_mixed_batch_core(encoded_batch.as_slice())
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
		// Cached path: a message verified here (e.g. during mempool admission) is a
		// cache hit when its block is imported. Returns the 20-byte signer on
		// success, or an empty Vec on failure (logged inside the pure fn).
		verify_one_message_cached(&message, &signature, &pub_key)
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	//! Determinism / correctness tests for the parallel batch host function.
	//!
	//! These exercise `verify_batch_core` (the native body of
	//! `verify_pqc_transaction_batch`) directly, against `verify_one_tx` (the
	//! native body of `verify_pqc_transaction`), proving the parallel path is
	//! bit-for-bit identical to the serial path and index-aligned.

	use super::*;
	use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};
	use blackchain_crypto_lib_rust::{create_wallet, sign_message, sign_transaction, BlackChainTxType};
	use fp_blackchain_crypto::BlackChainTransaction;
	use scale_codec::Encode;

	/// Build a genuinely-valid signed transaction and return its SCALE bytes
	/// (the exact payload `verify_one_tx` decodes) alongside the 20-byte signer.
	fn signed_tx_scale(nonce: u64) -> (Vec<u8>, [u8; 20]) {
		let (_mnemonic, key) = create_wallet("").expect("create_wallet failed");

		let mut tx = BlackChainTxType {
			chain_id: 42,
			nonce,
			max_priority_fee_per_gas: AlloyU256::from(1_000_000_000u64),
			max_fee_per_gas: AlloyU256::from(10_000_000_000u64),
			gas_limit: 21_000,
			to: Some(AlloyAddress::ZERO),
			value: AlloyU256::ZERO,
			data: AlloyBytes::default(),
			v: None,
			r: None,
			s: None,
			pqc_signature: None,
			pub_key: None,
		};
		sign_transaction(&mut tx, &key).expect("signing failed");

		let pqc_signature = tx.pqc_signature.as_ref().expect("signed tx has sig").to_vec();
		let pub_key = tx.pub_key.as_ref().expect("signed tx has pubkey").to_vec();

		let on_chain = BlackChainTransaction {
			chain_id: tx.chain_id,
			nonce: tx.nonce,
			max_priority_fee_per_gas: tx.max_priority_fee_per_gas.to_be_bytes::<32>(),
			max_fee_per_gas: tx.max_fee_per_gas.to_be_bytes::<32>(),
			gas_limit: tx.gas_limit,
			to: tx.to.map(|a| a.into_array()).unwrap_or([0u8; 20]),
			is_create: tx.to.is_none(),
			value: tx.value.to_be_bytes::<32>(),
			input: tx.data.to_vec(),
			v: tx.v.map(|v| v.to::<u64>()).unwrap_or(tx.chain_id * 2 + 35),
			r: [0u8; 32],
			s: [0u8; 32],
			pqc_signature,
			pub_key,
		};

		let encoded = on_chain.encode();
		let signer = {
			let out = verify_one_tx(&encoded);
			assert_eq!(out.len(), 20, "freshly-signed tx must verify");
			let mut a = [0u8; 20];
			a.copy_from_slice(&out);
			a
		};
		(encoded, signer)
	}

	/// The serial reference: concatenate the normalised per-item result of
	/// `verify_one_tx` for each item, exactly as the batch is specified to do.
	fn serial_reference(items: &[Vec<u8>]) -> Vec<u8> {
		let mut out = Vec::with_capacity(items.len() * 20);
		for it in items {
			let r = verify_one_tx(it);
			if r.len() == 20 {
				out.extend_from_slice(&r);
			} else {
				out.extend_from_slice(&[0u8; 20]);
			}
		}
		out
	}

	#[test]
	fn batch_matches_serial_and_is_index_aligned() {
		// Three distinct signers (distinct keypairs -> distinct addresses) plus
		// two deliberately-invalid items interleaved, so a shuffled or
		// misaligned result would be detectable.
		let (tx0, s0) = signed_tx_scale(0);
		let (tx1, s1) = signed_tx_scale(1);
		let (tx2, s2) = signed_tx_scale(2);
		assert!(s0 != s1 && s1 != s2 && s0 != s2, "signers must be distinct");

		let garbage_decode_fail = vec![0xFFu8; 8]; // not a valid SCALE tx
		let mut tampered = tx1.clone();
		*tampered.last_mut().unwrap() ^= 0xFF; // flip a pubkey byte -> bad sig

		let items = vec![
			tx0.clone(),              // 0: valid  -> s0
			garbage_decode_fail,      // 1: decode fail -> zeros
			tx1.clone(),              // 2: valid  -> s1
			tampered,                 // 3: valid decode, bad sig -> zeros
			tx2.clone(),              // 4: valid  -> s2
		];

		let envelope = items.encode();
		let batch = verify_batch_core(&envelope);
		let serial = serial_reference(&items);

		assert_eq!(batch.len(), items.len() * 20, "20*N output length");
		assert_eq!(batch, serial, "parallel batch must equal serial reference");

		// Explicit index alignment.
		assert_eq!(&batch[0..20], &s0, "index 0 -> signer 0");
		assert_eq!(&batch[20..40], &[0u8; 20], "index 1 -> decode-fail sentinel");
		assert_eq!(&batch[40..60], &s1, "index 2 -> signer 1");
		assert_eq!(&batch[60..80], &[0u8; 20], "index 3 -> bad-sig sentinel");
		assert_eq!(&batch[80..100], &s2, "index 4 -> signer 2");
	}

	#[test]
	fn batch_is_deterministic_across_runs() {
		let (tx0, _) = signed_tx_scale(7);
		let (tx1, _) = signed_tx_scale(8);
		let items = vec![tx0, tx1];
		let envelope = items.encode();

		let a = verify_batch_core(&envelope);
		let b = verify_batch_core(&envelope);
		let c = verify_batch_core(&envelope);
		assert_eq!(a, b);
		assert_eq!(b, c);
	}

	#[test]
	fn empty_batch_returns_empty() {
		let items: Vec<Vec<u8>> = Vec::new();
		let envelope = items.encode();
		assert!(verify_batch_core(&envelope).is_empty());
	}

	#[test]
	fn bad_envelope_returns_empty() {
		// Not a valid SCALE `Vec<Vec<u8>>`.
		assert!(verify_batch_core(&[0xFFu8, 0xFF, 0xFF]).is_empty());
	}

	// -----------------------------------------------------------------------
	// Demonstration tests: core distribution + tamper rejection at scale.
	//
	// These are heavy (real PQC signing + verification) — run with --release:
	//   cargo test -p pallet-ethereum-blackchain-hf --release -- --nocapture
	// Pin the worker count to watch the division change:
	//   RAYON_NUM_THREADS=4 cargo test ... -- --nocapture batch_work_is_spread
	// -----------------------------------------------------------------------

	/// Every altered transaction in a large mixed batch is rejected (20 zero
	/// bytes), and every untouched one still recovers the correct signer — at
	/// the exact index, regardless of parallel scheduling.
	#[test]
	fn batch_rejects_every_tampered_tx() {
		let (base, signer) = signed_tx_scale(0);
		let n = 48usize;

		let mut items = Vec::with_capacity(n);
		let mut expect_valid = Vec::with_capacity(n);
		for i in 0..n {
			match i % 3 {
				// Untouched valid tx.
				0 => {
					items.push(base.clone());
					expect_valid.push(true);
				}
				// Flip a public-key byte (last field) -> signature no longer
				// matches the recovered address.
				1 => {
					let mut t = base.clone();
					*t.last_mut().unwrap() ^= 0xFF;
					items.push(t);
					expect_valid.push(false);
				}
				// Flip a byte inside the composite signature region.
				_ => {
					let mut t = base.clone();
					let mid = t.len() / 2;
					t[mid] ^= 0xFF;
					items.push(t);
					expect_valid.push(false);
				}
			}
		}

		let out = verify_batch_core(&items.encode());
		assert_eq!(out.len(), n * 20);

		let mut rejected = 0usize;
		for i in 0..n {
			let chunk = &out[i * 20..i * 20 + 20];
			if expect_valid[i] {
				assert_eq!(chunk, &signer, "untouched tx #{i} must recover signer");
			} else {
				assert_eq!(chunk, &[0u8; 20], "altered tx #{i} must be rejected");
				rejected += 1;
			}
		}
		println!(
			"tamper test: {n} txs, {rejected} altered -> all rejected, {} valid -> all accepted",
			n - rejected
		);
		assert_eq!(rejected, n - n.div_ceil(3));
	}

	/// The batch work is distributed across every CPU core. We mirror
	/// `verify_batch_core`'s `par_iter` and record which rayon worker thread
	/// handled each item, then assert all cores participated and the load is
	/// roughly balanced (uniform ~1.6 ms/item + work-stealing => near-even).
	#[test]
	fn batch_work_is_spread_across_all_cores() {
		use rayon::prelude::*;
		use std::sync::Mutex;

		let cores = rayon::current_num_threads();
		let (base, _) = signed_tx_scale(0);
		let n = (cores * 16).max(32);
		let items: Vec<Vec<u8>> = core::iter::repeat_with(|| base.clone()).take(n).collect();

		let counts: Vec<Mutex<usize>> = (0..cores).map(|_| Mutex::new(0)).collect();
		let results: Vec<Vec<u8>> = items
			.par_iter()
			.map(|enc| {
				if let Some(idx) = rayon::current_thread_index() {
					if idx < cores {
						*counts[idx].lock().unwrap() += 1;
					}
				}
				verify_one_tx(enc)
			})
			.collect();

		// Verification itself still succeeded for every item.
		assert!(results.iter().all(|r| r.len() == 20));

		let per_core: Vec<usize> = counts.iter().map(|c| *c.lock().unwrap()).collect();
		let used = per_core.iter().filter(|&&c| c > 0).count();
		let mean = n as f64 / cores as f64;

		println!("core distribution: {cores} cores, {n} txs, mean {mean:.1}/core");
		for (i, c) in per_core.iter().enumerate() {
			let bar = "#".repeat(*c);
			println!("  core {i:2}: {c:4}  {bar}");
		}

		assert_eq!(used, cores, "expected all {cores} cores to handle work, only {used} did");
		if cores > 1 {
			let max = *per_core.iter().max().unwrap();
			assert!(
				(max as f64) <= mean * 2.0,
				"load imbalance: busiest core did {max}, mean is {mean:.1}",
			);
		}
	}

	/// The real `verify_batch_core` is meaningfully faster than verifying the
	/// same transactions serially — i.e. the parallelism is actually paying off.
	#[test]
	fn batch_is_faster_than_serial() {
		use std::time::Instant;

		let cores = rayon::current_num_threads();
		let (base, _) = signed_tx_scale(0);
		let n = (cores * 8).max(16);
		let items: Vec<Vec<u8>> = core::iter::repeat_with(|| base.clone()).take(n).collect();
		use rayon::prelude::*;

		// Measure the PURE (uncached) path on both sides so this reflects real
		// crypto parallelism, not the memo cache (the items are identical clones,
		// which the cache would otherwise collapse to a single verify).
		let _: Vec<Vec<u8>> = items.par_iter().map(|it| verify_one_tx(it)).collect();

		let t0 = Instant::now();
		let mut serial = Vec::with_capacity(n * 20);
		for it in &items {
			let r = verify_one_tx(it);
			if r.len() == 20 {
				serial.extend_from_slice(&r);
			} else {
				serial.extend_from_slice(&[0u8; 20]);
			}
		}
		let serial_t = t0.elapsed();

		let t1 = Instant::now();
		let parallel: Vec<u8> = {
			let chunks: Vec<Vec<u8>> = items
				.par_iter()
				.map(|it| {
					let r = verify_one_tx(it);
					if r.len() == 20 {
						r
					} else {
						alloc::vec![0u8; 20]
					}
				})
				.collect();
			let mut flat = Vec::with_capacity(n * 20);
			for c in chunks {
				flat.extend_from_slice(&c);
			}
			flat
		};
		let parallel_t = t1.elapsed();

		assert_eq!(serial, parallel, "parallel result must equal serial");

		let speedup = serial_t.as_secs_f64() / parallel_t.as_secs_f64();
		println!(
			"timing: {n} txs on {cores} cores — serial {serial_t:?}, parallel {parallel_t:?}, speedup {speedup:.2}x",
		);
		if cores > 1 {
			assert!(
				speedup > 1.2,
				"expected real speedup on {cores} cores, got only {speedup:.2}x",
			);
		}
	}

	// -----------------------------------------------------------------------
	// Mixed-batch tests (verify_mixed_batch_core): EVM `Transaction` items and
	// generic `Message` items (native transfers / sudo) verified in ONE pass.
	// -----------------------------------------------------------------------

	/// Build a genuinely-signed generic message item and return the
	/// `PqcBatchItem::Message` plus its 20-byte signer.
	fn signed_message_item(tag: &[u8]) -> (PqcBatchItem, [u8; 20]) {
		let (_m, key) = create_wallet("").expect("create_wallet failed");
		let message = tag.to_vec();
		let signature = sign_message(&message, &key).expect("sign_message failed");
		let pub_key = key.public_key().to_bytes();
		let signer = {
			let out = verify_one_message(&message, &signature, &pub_key);
			assert_eq!(out.len(), 20, "freshly-signed message must verify");
			let mut a = [0u8; 20];
			a.copy_from_slice(&out);
			a
		};
		(
			PqcBatchItem::Message {
				message,
				signature,
				pub_key,
			},
			signer,
		)
	}

	#[test]
	fn mixed_batch_verifies_evm_and_message_items_index_aligned() {
		// Interleave EVM transactions and generic messages, plus one tampered item
		// of each kind, so any misroute or misalignment is detectable.
		let (tx0, evm0) = signed_tx_scale(0);
		let (msg1, sig1) = signed_message_item(b"blackchain-native-transfer-#1");
		let (tx2, evm2) = signed_tx_scale(1);
		let (msg3, sig3) = signed_message_item(b"blackchain-native-transfer-#3");
		assert!(evm0 != evm2 && sig1 != sig3, "signers must be distinct");

		// Tamper an EVM item (flip pubkey byte) and a message item (flip sig byte).
		let mut tx_bad = tx0.clone();
		*tx_bad.last_mut().unwrap() ^= 0xFF;
		let msg_bad = match signed_message_item(b"doomed").0 {
			PqcBatchItem::Message {
				message,
				mut signature,
				pub_key,
			} => {
				signature[0] ^= 0xFF;
				PqcBatchItem::Message {
					message,
					signature,
					pub_key,
				}
			}
			_ => unreachable!(),
		};

		let items = vec![
			PqcBatchItem::Transaction(tx0),  // 0: EVM valid -> evm0
			msg1,                            // 1: message valid -> sig1
			PqcBatchItem::Transaction(tx_bad), // 2: EVM bad -> zeros
			PqcBatchItem::Transaction(tx2),  // 3: EVM valid -> evm2
			msg3,                            // 4: message valid -> sig3
			msg_bad,                         // 5: message bad -> zeros
		];

		let out = verify_mixed_batch_core(&items.encode());
		assert_eq!(out.len(), items.len() * 20);
		assert_eq!(&out[0..20], &evm0, "idx0 EVM signer");
		assert_eq!(&out[20..40], &sig1, "idx1 message signer");
		assert_eq!(&out[40..60], &[0u8; 20], "idx2 tampered EVM -> zero");
		assert_eq!(&out[60..80], &evm2, "idx3 EVM signer");
		assert_eq!(&out[80..100], &sig3, "idx4 message signer");
		assert_eq!(&out[100..120], &[0u8; 20], "idx5 tampered message -> zero");
	}

	#[test]
	fn mixed_batch_matches_per_item_serial() {
		let (tx0, _) = signed_tx_scale(0);
		let (msg, _) = signed_message_item(b"serial-ref");
		let items = vec![PqcBatchItem::Transaction(tx0.clone()), msg.clone()];

		let batch = verify_mixed_batch_core(&items.encode());

		// Serial reference: verify each item with its own primitive.
		let mut serial = Vec::new();
		let r0 = verify_one_tx(&tx0);
		serial.extend_from_slice(if r0.len() == 20 { &r0 } else { &[0u8; 20] });
		if let PqcBatchItem::Message {
			message,
			signature,
			pub_key,
		} = &msg
		{
			let r1 = verify_one_message(message, signature, pub_key);
			serial.extend_from_slice(if r1.len() == 20 { &r1 } else { &[0u8; 20] });
		}
		assert_eq!(batch, serial, "mixed parallel batch must equal serial");
	}

	#[test]
	fn mixed_batch_bad_envelope_returns_empty() {
		assert!(verify_mixed_batch_core(&[0xFFu8, 0xFF, 0xFF]).is_empty());
	}

	// -----------------------------------------------------------------------
	// Verify-cache tests (verify_one_tx_cached / verify_one_message_cached):
	// the memo must return the SAME result as the pure path, cache successes,
	// never cache failures, and never collide across inputs or schemes.
	// -----------------------------------------------------------------------

	#[test]
	fn cache_hit_matches_pure_result() {
		verify_cache::clear();
		let (tx, signer) = signed_tx_scale(0);
		let key = verify_cache::tx_key(&tx);

		assert!(verify_cache::get(&key).is_none(), "cold: not cached yet");
		let first = verify_one_tx_cached(&tx); // miss -> verifies + caches
		assert_eq!(first, signer.to_vec());
		assert_eq!(verify_cache::get(&key), Some(signer), "populated on success");
		let second = verify_one_tx_cached(&tx); // hit
		assert_eq!(second, first, "cache hit returns identical result");

		// Message path too.
		let (item, msig) = signed_message_item(b"cache-msg");
		if let PqcBatchItem::Message {
			message,
			signature,
			pub_key,
		} = item
		{
			let mkey = verify_cache::msg_key(&message, &signature, &pub_key);
			assert!(verify_cache::get(&mkey).is_none());
			let m1 = verify_one_message_cached(&message, &signature, &pub_key);
			assert_eq!(m1, msig.to_vec());
			assert_eq!(verify_cache::get(&mkey), Some(msig));
		}
	}

	#[test]
	fn cache_stats_count_hits_and_misses() {
		// A unique nonce → a tx no other test touches, so its first lookup is a cold
		// MISS and its second is a HIT. Counters are process-global and other tests
		// run concurrently, so assert only that each counter strictly increased
		// (both are monotonic, so our own miss/hit can never be subtracted away).
		let (tx, _) = signed_tx_scale(222);

		let (_, m0) = cache_stats();
		let _ = verify_one_tx_cached(&tx); // cold → miss + cache
		let (h1, m1) = cache_stats();
		assert!(m1 > m0, "a cold verify records a miss");

		let _ = verify_one_tx_cached(&tx); // warm → hit
		let (h2, _) = cache_stats();
		assert!(h2 > h1, "a repeat verify records a hit");
	}

	#[test]
	fn cache_does_not_store_failures() {
		verify_cache::clear();
		// A tampered tx fails verification and must NOT be cached.
		let (mut tx, _) = signed_tx_scale(1);
		*tx.last_mut().unwrap() ^= 0xFF;
		let key = verify_cache::tx_key(&tx);
		let out = verify_one_tx_cached(&tx);
		assert!(out.is_empty(), "tampered tx must fail");
		assert!(verify_cache::get(&key).is_none(), "failures are not cached");
	}

	#[test]
	fn cache_keys_are_distinct_across_inputs_and_schemes() {
		let (tx_a, _) = signed_tx_scale(0);
		let (tx_b, _) = signed_tx_scale(1);
		assert_ne!(verify_cache::tx_key(&tx_a), verify_cache::tx_key(&tx_b), "distinct txs");

		// Same raw bytes fed as a tx vs. as a message component must not collide,
		// thanks to the one-byte scheme tag.
		let m = vec![1u8, 2, 3];
		let s = vec![4u8, 5, 6];
		let p = vec![7u8, 8, 9];
		assert_ne!(
			verify_cache::tx_key(&m),
			verify_cache::msg_key(&m, &s, &p),
			"scheme tags keep the two paths from colliding",
		);
		// Length-delimiting prevents (m‖s) ambiguity: ([1],[2,3]) != ([1,2],[3]).
		assert_ne!(
			verify_cache::msg_key(&[1], &[2, 3], &p),
			verify_cache::msg_key(&[1, 2], &[3], &p),
			"length-delimited message key is unambiguous",
		);
	}
}
