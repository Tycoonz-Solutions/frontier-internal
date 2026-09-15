// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(unused_crate_dependencies)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::min;

use fp_evm::{ExitError, ExitSucceed, LinearCostPrecompile, PrecompileFailure};
use pallet_ethereum_blackchain_hf::blackchain_crypto;

/// The identity precompile.
pub struct Identity;

impl LinearCostPrecompile for Identity {
	const BASE: u64 = 15;
	const WORD: u64 = 3;

	fn execute(input: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		Ok((ExitSucceed::Returned, input.to_vec()))
	}
}

/// The BlackChain hybrid post-quantum signature-verification precompile.
///
/// Address: `0x0000000000000000000000000000000000000001`
///
/// This lets EVM smart contracts verify a Dilithium5 + P-521 + Ed448 composite
/// signature on-chain (the post-quantum analogue of Ethereum's `ecrecover`).
///
/// ## Input layout (packed — call via low-level `staticcall`)
/// ```text
///   [ 0 ..  32]                     tx_hash        (32 bytes)
///   [32 ..  40]                     chain_id       (u64, big-endian)
///   [40 ..  40 + 2782]              composite_pub_key (2782 bytes)
///   [40 + 2782 ..]                  composite_signature (exactly 4873 bytes)
/// ```
///
/// ## Output
///   A single 32-byte word: the 20-byte recovered sender address, left-zero-padded
///   (same shape as `ecrecover`), or 32 zero bytes if verification fails.
///
/// ## Native / WASM parity
///   Both execution environments go through the `verify_pqc_signature` host
///   function, so on-chain (WASM) execution and `eth_call` (native) return the
///   SAME result. The composite crypto is not WASM-safe, hence the host function.
///
/// ## Gas
///   BASE = 160_000 (reflects the measured ~2.57 ms ML-DSA-87 + P-521 + Ed448 verify).
pub struct BlackChainVerify;

impl BlackChainVerify {
	/// Composite public key size: ML-DSA-87(2592) + P521(133) + Ed448(57).
	const COMPOSITE_PK_SIZE: usize = 2782;
	/// Exact composite signature size: ML-DSA-87(4627) + P521(132, fixed r‖s) + Ed448(114).
	/// All three sub-signatures are fixed-width; the crypto library rejects any
	/// other length (anti-malleability/padding).
	const COMPOSITE_SIG_SIZE: usize = 4873;
	/// Fixed header: 32-byte hash + 8-byte big-endian chain_id.
	const HEADER_SIZE: usize = 32 + 8;
}

impl LinearCostPrecompile for BlackChainVerify {
	// Gas must stay ABOVE the real verification cost or a block full of these calls
	// overruns the weight budget (consensus DoS). Derivation on this runtime:
	//   WeightPerGas = 20_000 ref_time/gas  → 1 gas ≈ 0.00002 ms, i.e. 50_000 gas/ms.
	//   Measured ML-DSA-87 + P-521 + Ed448 verify (host-fn path) ≈ 2.568 ms
	//     ⇒ break-even ≈ 128_400 gas; with ~1.25× margin ⇒ 160_000.
	// (Was 100_000 for the 1.6 ms crystals-Dilithium5 verify — under-priced after the
	// 2026-08-05 FIPS 204 ML-DSA-87 migration.) MUST be re-derived from a benchmark on
	// target validator hardware before production, kept in sync with `weights.rs`.
	const BASE: u64 = 160_000;
	const WORD: u64 = 0;

	fn execute(input: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		// The composite signature is fixed-width, so a well-formed packed input has
		// exactly this length. Reject anything else up front (mirrors the exact-length
		// rule enforced by the crypto library).
		let expected_input =
			Self::HEADER_SIZE + Self::COMPOSITE_PK_SIZE + Self::COMPOSITE_SIG_SIZE;
		if input.len() != expected_input {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("BlackChainVerify: bad input length".into()),
			});
		}

		// Parse the packed input (bounds already guaranteed by the length check above).
		let hash = input[..32].to_vec();
		let mut chain_id_bytes = [0u8; 8];
		chain_id_bytes.copy_from_slice(&input[32..40]);
		let chain_id = u64::from_be_bytes(chain_id_bytes);
		let pub_key = input[Self::HEADER_SIZE..Self::HEADER_SIZE + Self::COMPOSITE_PK_SIZE].to_vec();
		let pqc_sig = input[Self::HEADER_SIZE + Self::COMPOSITE_PK_SIZE..].to_vec();

		// Full composite verification runs natively (crypto is not WASM-safe) via the
		// `verify_pqc_signature` host function. In native runtime execution this is a
		// direct call; in WASM it crosses the host boundary. Same result either way.
		let recovered = blackchain_crypto::verify_pqc_signature(hash, chain_id, pub_key, pqc_sig);

		let mut output = [0u8; 32];
		// A 20-byte result is a successful recovery. Guard against the zero address:
		// output(0) is indistinguishable from the failure response, and a legitimately
		// verified zero address is cryptographically infeasible.
		if recovered.len() == 20 && recovered != alloc::vec![0u8; 20] {
			output[12..].copy_from_slice(&recovered);
		}
		Ok((ExitSucceed::Returned, output.to_vec()))
	}
}

/// Precompile: verify a composite PQC signature over an ARBITRARY MESSAGE — the generic
/// `sign_message` / `verify_message` scheme, i.e. what a wallet's `personal_sign` produces.
///
/// Address: `0x0000000000000000000000000000000000000404`
///
/// Unlike `BlackChainVerify` (0x01), which verifies a *transaction* signing hash bound to a
/// chain id, this verifies a signature over a caller-chosen message with the generic scheme
/// (keccak256(message) internally, zeroed entanglement nonce). Use it to verify a
/// `personal_sign` / `signMessage` signature on-chain ("sign THIS message to prove you hold
/// the key").
///
/// ## Input layout (packed)
/// ```text
///   [ 0 .. 2782 )        composite_pub_key   (2782 bytes)
///   [ 2782 .. 7655 )     composite_signature (4873 bytes)
///   [ 7655 .. ]          message             (arbitrary length, may be empty)
/// ```
/// ## Output
///   32-byte word: left-padded 20-byte signer address `keccak256(pub_key)[12:]`, or 32 zero
///   bytes if the signature is invalid.
pub struct BlackChainMessageVerify;

impl BlackChainMessageVerify {
	const COMPOSITE_PK_SIZE: usize = 2782;
	const COMPOSITE_SIG_SIZE: usize = 4873;
	/// Fixed prefix before the variable-length message: pub_key ‖ signature.
	const FIXED_PREFIX: usize = Self::COMPOSITE_PK_SIZE + Self::COMPOSITE_SIG_SIZE; // 7655
}

impl LinearCostPrecompile for BlackChainMessageVerify {
	// Same composite verify cost as `BlackChainVerify` (0x01); WORD prices the
	// variable-length message (a keccak pass over it). Keep BASE in sync with 0x01.
	const BASE: u64 = 160_000;
	const WORD: u64 = 3;

	fn execute(input: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		if input.len() < Self::FIXED_PREFIX {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("BlackChainMessageVerify: input too short".into()),
			});
		}
		// Bounds guaranteed by the length check above.
		let pub_key = input[..Self::COMPOSITE_PK_SIZE].to_vec();
		let signature = input[Self::COMPOSITE_PK_SIZE..Self::FIXED_PREFIX].to_vec();
		let message = input[Self::FIXED_PREFIX..].to_vec();

		// Generic-message verification via the `verify_pqc_message` host function (native
		// crypto in both native and WASM execution).
		let recovered = blackchain_crypto::verify_pqc_message(message, signature, pub_key);

		let mut output = [0u8; 32];
		if recovered.len() == 20 && recovered != alloc::vec![0u8; 20] {
			output[12..].copy_from_slice(&recovered);
		}
		Ok((ExitSucceed::Returned, output.to_vec()))
	}
}

/// The ripemd precompile.
pub struct Ripemd160;

impl LinearCostPrecompile for Ripemd160 {
	const BASE: u64 = 600;
	const WORD: u64 = 120;

	fn execute(input: &[u8], _cost: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		use ripemd::Digest;

		let mut ret = [0u8; 32];
		ret[12..32].copy_from_slice(&ripemd::Ripemd160::digest(input));
		Ok((ExitSucceed::Returned, ret.to_vec()))
	}
}

/// The sha256 precompile.
pub struct Sha256;

impl LinearCostPrecompile for Sha256 {
	const BASE: u64 = 60;
	const WORD: u64 = 12;

	fn execute(input: &[u8], _cost: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		let ret = sp_io::hashing::sha2_256(input);
		Ok((ExitSucceed::Returned, ret.to_vec()))
	}
}

/// The ECRecoverPublicKey precompile.
/// Similar to ECRecover, but returns the pubkey (not the corresponding Ethereum address)
pub struct ECRecoverPublicKey;

impl LinearCostPrecompile for ECRecoverPublicKey {
	const BASE: u64 = 3000;
	const WORD: u64 = 0;

	fn execute(i: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		let mut input = [0u8; 128];
		input[..min(i.len(), 128)].copy_from_slice(&i[..min(i.len(), 128)]);

		let mut msg = [0u8; 32];
		let mut sig = [0u8; 65];

		msg[0..32].copy_from_slice(&input[0..32]);
		sig[0..32].copy_from_slice(&input[64..96]);
		sig[32..64].copy_from_slice(&input[96..128]);
		sig[64] = input[63];

		let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig, &msg).map_err(|_| {
			PrecompileFailure::Error {
				exit_status: ExitError::Other("Public key recover failed".into()),
			}
		})?;

		Ok((ExitSucceed::Returned, pubkey.to_vec()))
	}
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
	use super::*;
	use pallet_evm_test_vector_support::test_precompile_test_vectors;

	// NOTE: the upstream secp256k1 `ecRecover.json` consensus vectors no longer apply
	// at 0x01 — that precompile is now the BlackChain post-quantum verifier
	// (`BlackChainVerify`), which uses a different algorithm and input ABI. PQC
	// verification is covered by the crypto library's own test suite and by the
	// pallet-ethereum BlackChain tests.

	#[test]
	fn process_consensus_tests_for_sha256() -> Result<(), String> {
		test_precompile_test_vectors::<Sha256>("../testdata/common_sha256.json")?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_ripemd160() -> Result<(), String> {
		test_precompile_test_vectors::<Ripemd160>("../testdata/common_ripemd.json")?;
		Ok(())
	}

	// ── BlackChainVerify (0x01) ──────────────────────────────────────────────
	//
	// The upstream secp256k1 `ecRecover.json` consensus vectors no longer apply at
	// 0x01 — that address is now the post-quantum verifier, with a different
	// algorithm and input ABI. These tests replace that lost coverage using REAL
	// Dilithium5 + P-521 + Ed448 signatures.

	mod blackchain_verify {
		use super::*;
		use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};
		use blackchain_crypto_lib_rust::{
			sign_transaction, transaction::types::BlackChainTxType, BlackChainPrivateKey,
		};

		const PK_SIZE: usize = 2782;
		const SIG_SIZE: usize = 4873;
		const HEADER: usize = 40; // 32-byte hash ‖ 8-byte big-endian chain_id
		const EXPECTED_INPUT: usize = HEADER + PK_SIZE + SIG_SIZE; // 7695
		const CHAIN_ID: u64 = 42;

		/// A real signed transaction, reduced to exactly what the precompile consumes:
		/// `(signing_hash, chain_id, composite_pub_key, composite_signature, signer)`.
		fn signed_vector(seed: u8) -> ([u8; 32], u64, Vec<u8>, Vec<u8>, [u8; 20]) {
			let (key, _) = BlackChainPrivateKey::generate(&[seed.wrapping_add(1); 64])
				.expect("keygen failed");
			let mut tx = BlackChainTxType {
				chain_id: CHAIN_ID,
				nonce: 0,
				max_priority_fee_per_gas: AlloyU256::from(1u64),
				max_fee_per_gas: AlloyU256::from(1u64),
				gas_limit: 21_000,
				to: Some(AlloyAddress::from([0xAB; 20])),
				value: AlloyU256::ZERO,
				data: AlloyBytes::new(),
				v: Some(AlloyU256::from(CHAIN_ID * 2 + 35)),
				r: Some(AlloyU256::ZERO),
				s: Some(AlloyU256::ZERO),
				pqc_signature: None,
				pub_key: None,
			};
			sign_transaction(&mut tx, &key).expect("composite signing failed");

			let hash = tx.signature_hash();
			let pub_key = tx.pub_key.clone().expect("pub_key").to_vec();
			let sig = tx.pqc_signature.clone().expect("signature").to_vec();
			let mut signer = [0u8; 20];
			signer.copy_from_slice(key.public_key().derive_address().as_slice());
			(hash, CHAIN_ID, pub_key, sig, signer)
		}

		/// Packs the precompile's tightly-packed ABI.
		fn encode_input(hash: &[u8; 32], chain_id: u64, pub_key: &[u8], sig: &[u8]) -> Vec<u8> {
			let mut input = Vec::with_capacity(EXPECTED_INPUT);
			input.extend_from_slice(hash);
			input.extend_from_slice(&chain_id.to_be_bytes());
			input.extend_from_slice(pub_key);
			input.extend_from_slice(sig);
			input
		}

		#[test]
		fn abi_layout_matches_the_documented_offsets() {
			let (hash, chain_id, pk, sig, _) = signed_vector(1);
			let input = encode_input(&hash, chain_id, &pk, &sig);
			assert_eq!(input.len(), EXPECTED_INPUT, "packed input must be 7695 bytes");
			assert_eq!(&input[..32], &hash[..]);
			assert_eq!(&input[32..40], &chain_id.to_be_bytes());
			assert_eq!(&input[40..40 + PK_SIZE], &pk[..]);
			assert_eq!(&input[40 + PK_SIZE..], &sig[..]);
			assert_eq!(pk.len(), PK_SIZE);
			assert_eq!(sig.len(), SIG_SIZE);
		}

		#[test]
		fn valid_signature_recovers_the_signer_address() {
			let (hash, chain_id, pk, sig, signer) = signed_vector(2);
			let input = encode_input(&hash, chain_id, &pk, &sig);

			let (exit, output) = BlackChainVerify::execute(&input, 0).expect("must not error");
			assert!(matches!(exit, ExitSucceed::Returned));
			assert_eq!(output.len(), 32, "output must be one 32-byte word");
			assert_eq!(&output[..12], &[0u8; 12], "address must be left-zero-padded");
			assert_eq!(
				&output[12..],
				&signer[..],
				"recovered address must equal keccak(pub_key)[12..]"
			);
		}

		#[test]
		fn tampered_signature_returns_zero_word() {
			let (hash, chain_id, pk, mut sig, _) = signed_vector(3);
			sig[0] ^= 0xFF; // still exactly SIG_SIZE bytes
			let input = encode_input(&hash, chain_id, &pk, &sig);

			let (_, output) = BlackChainVerify::execute(&input, 0).expect("must not error");
			assert_eq!(
				output,
				vec![0u8; 32],
				"a cryptographically invalid signature must return the zero word"
			);
		}

		#[test]
		fn each_tampered_sub_signature_returns_zero_word() {
			// Composite is [ML-DSA-87 4627 ‖ P-521 132 ‖ Ed448 114] — corrupting any leg fails.
			// Offsets land inside each leg: dil [0,4627), p521 [4627,4759), ed448 [4759,4873).
			for (leg, off) in [("mldsa87", 10usize), ("p521", 4637), ("ed448", 4769)] {
				let (hash, chain_id, pk, mut sig, _) = signed_vector(4);
				sig[off] ^= 0xFF;
				let input = encode_input(&hash, chain_id, &pk, &sig);
				let (_, output) = BlackChainVerify::execute(&input, 0).expect("must not error");
				assert_eq!(output, vec![0u8; 32], "tampered {leg} leg must fail");
			}
		}

		#[test]
		fn wrong_hash_returns_zero_word() {
			let (_, chain_id, pk, sig, _) = signed_vector(5);
			let input = encode_input(&[0xAA; 32], chain_id, &pk, &sig);
			let (_, output) = BlackChainVerify::execute(&input, 0).expect("must not error");
			assert_eq!(output, vec![0u8; 32], "signature must be bound to the hash");
		}

		#[test]
		fn wrong_chain_id_returns_zero_word() {
			// chain_id feeds the entanglement nonce, so a mismatch must not verify.
			let (hash, _, pk, sig, _) = signed_vector(6);
			let input = encode_input(&hash, 999, &pk, &sig);
			let (_, output) = BlackChainVerify::execute(&input, 0).expect("must not error");
			assert_eq!(output, vec![0u8; 32], "signature must be bound to the chain id");
		}

		#[test]
		fn mismatched_public_key_returns_zero_word() {
			let (hash, chain_id, _, sig, _) = signed_vector(7);
			let (_, _, other_pk, _, _) = signed_vector(8);
			let input = encode_input(&hash, chain_id, &other_pk, &sig);
			let (_, output) = BlackChainVerify::execute(&input, 0).expect("must not error");
			assert_eq!(output, vec![0u8; 32], "public key must match the signature");
		}

		#[test]
		fn non_exact_input_lengths_are_rejected() {
			let (hash, chain_id, pk, sig, _) = signed_vector(9);
			let valid = encode_input(&hash, chain_id, &pk, &sig);

			let mut too_short = valid.clone();
			too_short.pop();
			let mut too_long = valid.clone();
			too_long.push(0);

			for (name, input) in [
				("empty", Vec::new()),
				("one byte short", too_short),
				("one byte long", too_long),
				("header only", vec![0u8; HEADER]),
				("ecrecover-sized (128)", vec![0u8; 128]),
			] {
				match BlackChainVerify::execute(&input, 0) {
					Err(PrecompileFailure::Error { .. }) => {}
					other => panic!("{name}: expected a bad-input-length error, got {other:?}"),
				}
			}
		}

		#[test]
		fn valid_input_length_is_accepted() {
			// Guards the boundary from the other side: exactly 7695 bytes must NOT be
			// rejected for length (it may still fail verification and return zeros).
			let input = vec![0u8; EXPECTED_INPUT];
			let (_, output) = BlackChainVerify::execute(&input, 0)
				.expect("an exactly-sized input must not be a length error");
			assert_eq!(output, vec![0u8; 32], "all-zero input cannot verify");
		}

		#[test]
		fn gas_cost_reflects_pqc_verification() {
			// BASE must stay high enough that the ~2.57 ms composite verify (ML-DSA-87 +
			// P-521 + Ed448) cannot be invoked cheaply in a loop and overrun the block
			// weight budget; WORD is 0 because cost is input-size invariant. At
			// WeightPerGas = 20_000 ref_time/gas, 160_000 gas ≈ 3.2 ms of allocated
			// weight, ~1.25× over the measured 2.568 ms verify.
			assert_eq!(BlackChainVerify::BASE, 160_000);
			assert_eq!(BlackChainVerify::WORD, 0);
		}
	}
}
