// frame/ethereum/src/tests/blackchain.rs
//
// Production test suite for the BlackChain PQC transaction path.
//
// ## What this file covers
//
// The BlackChain path replaces secp256k1 ECDSA with a composite hybrid signature
// (Dilithium5 ‖ P-521 ‖ Ed448). A transaction flows through four stages, each of
// which is a distinct trust boundary and is exercised here:
//
//   1. `check_self_contained`      — structural gates, cheap economic pre-filter
//                                     (CR-2), then the FULL composite verification.
//                                     Runs natively at pool admission and block import.
//   2. `validate_self_contained`   — pool validation + mempool ordering tags.
//   3. `pre_dispatch_self_contained` — the STF gate: WASM-safe structural pin plus
//                                     full nonce/chain_id/fee/balance validation (CR-1).
//   4. `transact_blackchain`       — dispatch: executes through the EVM.
//
// Unlike a mocked-signature suite, the tests below sign with the REAL crypto
// library, so a regression in signing, verification, entanglement binding, address
// derivation or the signed-field set fails here rather than in production.
//
// Sections:
//   A. Test helpers (deterministic PQC wallets, real signing, state accessors)
//   B. Signature verification — positive and negative, with real signatures
//   C. Structural gates (size / shape)
//   D. Economic pre-filter, and its ordering before the expensive verify (CR-2)
//   E. STF validation: nonce, chain_id, balance (CR-1, HI-1)
//   F. WASM-side forgery pin in pre_dispatch (the block-author guard)
//   G. End-to-end dispatch: execution, balance, nonce, events, receipts
//   H. Determinism of the derived EIP-1559 transaction (replay-window invariant)
//   I. Pool validation and mempool ordering tags
//
// NOTE ON SCOPE: native↔WASM parity of `recover_blackchain_signer` cannot be
// asserted from a native unit test (the no_std branch delegates to a host
// function). It is covered by the on-chain integration suite (`pqc-tx-test`),
// which drives a real node whose block import executes the WASM runtime.

use super::*;
use crate::BlackChainTransaction;

use blackchain_crypto_lib_rust::{sign_transaction, BlackChainPrivateKey};

// ─────────────────────────────────────────────────────────────────────────────
// A. Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Protocol constants. Duplicated here on purpose: if the pallet's constants ever
/// change, these tests must fail loudly rather than silently follow along.
const COMPOSITE_PK_SIZE: usize = 2782;
const COMPOSITE_SIG_SIZE: usize = 4873;
/// The mock runtime's chain id (`pallet_evm::config_preludes::ChainId`).
const CHAIN_ID: u64 = 42;
/// The mock's `FixedGasPrice` base fee.
const BASE_FEE: u128 = 1;
/// Enough to cover `gas_limit * max_fee_per_gas` plus any transferred value.
const RICH: u64 = 1_000_000_000;

/// A deterministic composite PQC wallet.
struct PqcWallet {
	key: BlackChainPrivateKey,
	pub_key: Vec<u8>,
	address: H160,
}

/// Derives a deterministic wallet from a single seed byte — no OS randomness, so
/// tests are reproducible and fast.
fn pqc_wallet(seed: u8) -> PqcWallet {
	let seed_bytes = [seed.wrapping_add(1); 64];
	let (key, _) = BlackChainPrivateKey::generate(&seed_bytes).expect("keygen failed");
	let pub_key = key.public_key().to_bytes();
	let address = H160::from_slice(&sp_io::hashing::keccak_256(&pub_key)[12..]);
	PqcWallet {
		key,
		pub_key,
		address,
	}
}

/// Parameters for building a transaction, so individual tests can vary exactly one
/// field without repeating the whole struct.
struct TxSpec {
	nonce: u64,
	/// `None` means a contract-creation transaction.
	to: Option<H160>,
	value: u128,
	input: Vec<u8>,
	chain_id: u64,
	gas_limit: u64,
	max_fee_per_gas: u128,
	max_priority_fee_per_gas: u128,
}

impl Default for TxSpec {
	fn default() -> Self {
		Self {
			nonce: 0,
			to: Some(H160::from([0xAB; 20])),
			value: 0,
			input: vec![],
			chain_id: CHAIN_ID,
			gas_limit: 21_000,
			max_fee_per_gas: BASE_FEE,
			max_priority_fee_per_gas: 0,
		}
	}
}

/// Signs a transaction with the REAL composite scheme and converts it into the
/// on-chain `BlackChainTransaction`.
///
/// The `v/r/s` handling mirrors what `recover_blackchain_signer` reconstructs
/// (`v = chain_id*2+35`, `r = s = 0`), so the bytes verified on-chain are exactly
/// the bytes that were signed.
fn sign_tx(w: &PqcWallet, spec: &TxSpec) -> BlackChainTransaction {
	use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256};
	use blackchain_crypto_lib_rust::transaction::types::BlackChainTxType;

	let v = spec.chain_id * 2 + 35;
	let mut lib_tx = BlackChainTxType {
		chain_id: spec.chain_id,
		nonce: spec.nonce,
		max_priority_fee_per_gas: AlloyU256::from(spec.max_priority_fee_per_gas),
		max_fee_per_gas: AlloyU256::from(spec.max_fee_per_gas),
		gas_limit: spec.gas_limit,
		to: spec.to.map(|a| AlloyAddress::from_slice(a.as_bytes())),
		value: AlloyU256::from(spec.value),
		data: AlloyBytes::from(spec.input.clone()),
		v: Some(AlloyU256::from(v)),
		r: Some(AlloyU256::ZERO),
		s: Some(AlloyU256::ZERO),
		pqc_signature: None,
		pub_key: None,
	};
	sign_transaction(&mut lib_tx, &w.key).expect("composite signing failed");

	let mut to_bytes = [0u8; 20];
	if let Some(a) = spec.to {
		to_bytes.copy_from_slice(a.as_bytes());
	}

	BlackChainTransaction {
		chain_id: spec.chain_id,
		nonce: spec.nonce,
		max_priority_fee_per_gas: lib_tx.max_priority_fee_per_gas.to_be_bytes(),
		max_fee_per_gas: lib_tx.max_fee_per_gas.to_be_bytes(),
		gas_limit: spec.gas_limit,
		to: to_bytes,
		is_create: spec.to.is_none(),
		value: lib_tx.value.to_be_bytes(),
		input: spec.input.clone(),
		v,
		r: [0u8; 32],
		s: [0u8; 32],
		pqc_signature: lib_tx
			.pqc_signature
			.clone()
			.map(|b| b.to_vec())
			.expect("signature present after signing"),
		pub_key: lib_tx
			.pub_key
			.clone()
			.map(|b| b.to_vec())
			.expect("public key present after signing"),
	}
}

/// Convenience: a real signed transfer at `nonce` from `w`.
fn signed_transfer(w: &PqcWallet, nonce: u64, to: H160, value: u128) -> BlackChainTransaction {
	sign_tx(
		w,
		&TxSpec {
			nonce,
			to: Some(to),
			value,
			..Default::default()
		},
	)
}

fn call_of(tx: BlackChainTransaction) -> crate::Call<Test> {
	crate::Call::<Test>::transact_blackchain { transaction: tx }
}

/// Credits an EVM address so it can pay for gas.
fn fund(address: H160, amount: u64) {
	use frame_support::traits::Currency;
	use pallet_evm::AddressMapping;
	let account = <Test as pallet_evm::Config>::AddressMapping::into_account_id(address);
	let _ = pallet_balances::Pallet::<Test>::make_free_balance_be(&account, amount);
}

fn balance_of(address: H160) -> U256 {
	pallet_evm::Pallet::<Test>::account_basic(&address).0.balance
}

fn nonce_of(address: H160) -> U256 {
	pallet_evm::Pallet::<Test>::account_basic(&address).0.nonce
}

fn dispatch_info(call: &crate::Call<Test>) -> frame_support::dispatch::DispatchInfo {
	call.get_dispatch_info()
}

/// Runs `f` in a fresh externality with block number 1, so events are recorded.
fn with_ext<R>(f: impl FnOnce() -> R) -> R {
	let (_pairs, mut ext) = new_test_ext(1);
	ext.execute_with(|| {
		frame_system::Pallet::<Test>::set_block_number(1);
		f()
	})
}

/// Expect an `Invalid(Custom(InvalidSignature))` rejection.
fn assert_invalid_signature(res: Option<Result<H160, TransactionValidityError>>, ctx: &str) {
	match res {
		Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(code)))) => {
			assert_eq!(
				code,
				fp_evm::TransactionValidationError::InvalidSignature as u8,
				"{ctx}: expected InvalidSignature"
			);
		}
		other => panic!("{ctx}: expected InvalidSignature rejection, got {other:?}"),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// B. Signature verification — with REAL composite signatures
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn valid_signature_recovers_the_correct_sender() {
	with_ext(|| {
		let w = pqc_wallet(1);
		fund(w.address, RICH);
		let tx = signed_transfer(&w, 0, H160::from([0xCD; 20]), 0);

		match call_of(tx).check_self_contained() {
			Some(Ok(recovered)) => assert_eq!(
				recovered, w.address,
				"recovered sender must equal keccak(pub_key)[12..]"
			),
			other => panic!("valid signature must be accepted, got {other:?}"),
		}
	});
}

#[test]
fn address_is_keccak_of_public_key() {
	// Pins the address-derivation rule the whole security model rests on.
	let w = pqc_wallet(2);
	assert_eq!(w.pub_key.len(), COMPOSITE_PK_SIZE);
	let expected = H160::from_slice(&sp_io::hashing::keccak_256(&w.pub_key)[12..]);
	assert_eq!(w.address, expected);
}

#[test]
fn real_signature_has_exact_protocol_sizes() {
	let w = pqc_wallet(3);
	let tx = signed_transfer(&w, 0, H160::from([0x11; 20]), 0);
	assert_eq!(
		tx.pqc_signature.len(),
		COMPOSITE_SIG_SIZE,
		"composite signature must be exactly ML-DSA-87(4627)+P521(132)+Ed448(114)"
	);
	assert_eq!(tx.pub_key.len(), COMPOSITE_PK_SIZE);
}

#[test]
fn tampered_signature_fails_real_verification() {
	// THE test that was missing: a correctly-SIZED but cryptographically invalid
	// signature. It passes every structural gate and the economic pre-filter, so
	// only genuine composite verification can reject it.
	with_ext(|| {
		let w = pqc_wallet(4);
		fund(w.address, RICH);
		let mut tx = signed_transfer(&w, 0, H160::from([0x22; 20]), 0);
		tx.pqc_signature[0] ^= 0xFF;
		assert_eq!(tx.pqc_signature.len(), COMPOSITE_SIG_SIZE);

		assert_invalid_signature(call_of(tx).check_self_contained(), "tampered signature");
	});
}

#[test]
fn tampering_each_sub_signature_is_detected() {
	// The composite is [ML-DSA-87 4627 ‖ P-521 132 ‖ Ed448 114]. Corrupting ANY leg must
	// fail — this is what makes the scheme hybrid rather than "strongest-link".
	const DIL: usize = 4627;
	const P521: usize = 132;
	let offsets = [
		("dilithium5", 10usize),
		("p521", DIL + 10),
		("ed448", DIL + P521 + 10),
	];
	for (leg, off) in offsets {
		with_ext(|| {
			let w = pqc_wallet(5);
			fund(w.address, RICH);
			let mut tx = signed_transfer(&w, 0, H160::from([0x33; 20]), 0);
			tx.pqc_signature[off] ^= 0xFF;
			assert_invalid_signature(
				call_of(tx).check_self_contained(),
				&format!("tampered {leg} leg"),
			);
		});
	}
}

#[test]
fn signature_is_bound_to_every_transaction_field() {
	// A signature must not be transplantable onto a different transaction. Each
	// mutation below changes a signed field, so verification must fail.
	let base = TxSpec::default();
	let mutations: Vec<(&str, Box<dyn Fn(&mut BlackChainTransaction)>)> = vec![
		("nonce", Box::new(|t: &mut BlackChainTransaction| t.nonce += 1)),
		(
			"recipient",
			Box::new(|t: &mut BlackChainTransaction| t.to = [0xFF; 20]),
		),
		(
			"value",
			Box::new(|t: &mut BlackChainTransaction| t.value[31] = 9),
		),
		(
			"gas_limit",
			Box::new(|t: &mut BlackChainTransaction| t.gas_limit += 1),
		),
		(
			"input",
			Box::new(|t: &mut BlackChainTransaction| t.input = vec![0xDE, 0xAD]),
		),
		(
			"max_fee_per_gas",
			Box::new(|t: &mut BlackChainTransaction| t.max_fee_per_gas[31] = 99),
		),
	];

	for (field, mutate) in mutations {
		with_ext(|| {
			let w = pqc_wallet(6);
			fund(w.address, RICH);
			let mut tx = sign_tx(&w, &base);
			mutate(&mut tx);
			assert_invalid_signature(
				call_of(tx).check_self_contained(),
				&format!("mutated {field} must invalidate the signature"),
			);
		});
	}
}

#[test]
fn signature_from_one_wallet_cannot_be_paired_with_another_public_key() {
	// Swapping in a different pub_key changes the derived sender, so the attacker
	// cannot borrow someone else's identity for a signature they hold.
	with_ext(|| {
		let victim = pqc_wallet(7);
		let attacker = pqc_wallet(8);
		fund(victim.address, RICH);
		fund(attacker.address, RICH);

		let mut tx = signed_transfer(&attacker, 0, H160::from([0x44; 20]), 0);
		tx.pub_key = victim.pub_key.clone();

		assert_invalid_signature(
			call_of(tx).check_self_contained(),
			"attacker signature with victim public key",
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// C. Structural gates
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn check_self_contained_rejects_malformed_sizes() {
	// Every size that is not EXACTLY the protocol size must be rejected outright:
	// truncation, padding and emptiness are all anti-malleability concerns.
	let cases: Vec<(&str, usize, usize)> = vec![
		("empty pub_key", 0, COMPOSITE_SIG_SIZE),
		("empty signature", COMPOSITE_PK_SIZE, 0),
		("truncated signature", COMPOSITE_PK_SIZE, 100),
		("sig one byte short", COMPOSITE_PK_SIZE, COMPOSITE_SIG_SIZE - 1),
		("sig one byte long", COMPOSITE_PK_SIZE, COMPOSITE_SIG_SIZE + 1),
		("pk one byte short", COMPOSITE_PK_SIZE - 1, COMPOSITE_SIG_SIZE),
		("pk one byte long", COMPOSITE_PK_SIZE + 1, COMPOSITE_SIG_SIZE),
	];
	for (name, pk_len, sig_len) in cases {
		with_ext(|| {
			let tx = BlackChainTransaction {
				pub_key: vec![0x07; pk_len],
				pqc_signature: vec![0x09; sig_len],
				..sign_shape_only()
			};
			assert_invalid_signature(call_of(tx).check_self_contained(), name);
		});
	}
}

/// A structurally complete transaction whose signature bytes are junk — used to
/// test gates that must fire *before* any cryptography runs.
fn sign_shape_only() -> BlackChainTransaction {
	BlackChainTransaction {
		chain_id: CHAIN_ID,
		nonce: 0,
		max_priority_fee_per_gas: [0u8; 32],
		max_fee_per_gas: {
			let mut b = [0u8; 32];
			b[31] = 1;
			b
		},
		gas_limit: 21_000,
		to: [0xAB; 20],
		is_create: false,
		value: [0u8; 32],
		input: vec![],
		v: CHAIN_ID * 2 + 35,
		r: [0u8; 32],
		s: [0u8; 32],
		pqc_signature: vec![0x09; COMPOSITE_SIG_SIZE],
		pub_key: vec![0x07; COMPOSITE_PK_SIZE],
	}
}

/// The address a `sign_shape_only()` transaction claims to come from.
fn shape_only_origin() -> H160 {
	H160::from_slice(&sp_io::hashing::keccak_256(&vec![0x07u8; COMPOSITE_PK_SIZE])[12..])
}

// ─────────────────────────────────────────────────────────────────────────────
// D. Economic pre-filter (CR-2) and its ordering
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unfunded_sender_is_prefiltered_before_expensive_verify() {
	// CR-2: reject unpayable spam with two storage reads and a keccak, instead of
	// burning ~1.6 ms of Dilithium+P-521+Ed448 on a transaction that can never pay.
	// Asserting `Payment` (not InvalidSignature) proves the cheap gate ran FIRST —
	// this transaction's signature is junk and would have failed verification.
	with_ext(|| {
		let tx = sign_shape_only(); // sender has no balance
		match call_of(tx).check_self_contained() {
			Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Payment))) => {}
			other => panic!("expected economic Payment rejection before verify, got {other:?}"),
		}
	});
}

#[test]
fn prefilter_rejects_wrong_chain_id_before_verify() {
	with_ext(|| {
		let mut tx = sign_shape_only();
		tx.chain_id = 999;
		fund(shape_only_origin(), RICH);
		match call_of(tx).check_self_contained() {
			Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(code)))) => {
				assert_eq!(
					code,
					fp_evm::TransactionValidationError::InvalidChainId as u8,
					"wrong chain_id must be caught by the cheap pre-filter"
				);
			}
			other => panic!("expected InvalidChainId before verify, got {other:?}"),
		}
	});
}

#[test]
fn prefilter_does_not_reject_a_fully_valid_transaction() {
	// The subset invariant: the cheap pre-filter must never reject something the
	// authoritative validation would accept, or it would cause a consensus/mempool
	// divergence rather than a mere early-out.
	with_ext(|| {
		let w = pqc_wallet(9);
		fund(w.address, RICH);
		let tx = signed_transfer(&w, 0, H160::from([0x55; 20]), 1_000);
		assert!(
			matches!(call_of(tx).check_self_contained(), Some(Ok(_))),
			"a payable, correctly-signed tx must survive the pre-filter"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// E. STF validation: nonce / chain_id / balance (CR-1, HI-1)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pre_dispatch_accepts_the_expected_nonce() {
	// The positive control for section E — without it, "everything is rejected"
	// would pass all the negative tests below.
	with_ext(|| {
		let w = pqc_wallet(10);
		fund(w.address, RICH);
		let call = call_of(signed_transfer(&w, 0, H160::from([0x66; 20]), 0));
		let info = dispatch_info(&call);
		assert!(
			matches!(
				call.pre_dispatch_self_contained(&w.address, &info, 0),
				Some(Ok(()))
			),
			"a correct, funded, in-order transaction must pass the STF gate"
		);
	});
}

#[test]
fn pre_dispatch_rejects_stale_nonce_replay() {
	// CR-1: the confirmed double-spend. Account has advanced to nonce 3; replaying
	// nonce 0 must be rejected as Stale by the STF, not merely deduplicated by the
	// transaction pool's transient hash cache.
	with_ext(|| {
		use pallet_evm::AddressMapping;
		let w = pqc_wallet(11);
		fund(w.address, RICH);
		let account = <Test as pallet_evm::Config>::AddressMapping::into_account_id(w.address);
		frame_system::Account::<Test>::mutate(&account, |a| a.nonce = 3);

		let call = call_of(signed_transfer(&w, 0, H160::from([0x77; 20]), 0));
		let info = dispatch_info(&call);
		assert_eq!(
			call.pre_dispatch_self_contained(&w.address, &info, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Stale
			))),
			"stale nonce must be rejected by the STF (replay / double-spend guard)"
		);
	});
}

#[test]
fn pre_dispatch_rejects_future_nonce() {
	with_ext(|| {
		let w = pqc_wallet(12);
		fund(w.address, RICH);
		let call = call_of(signed_transfer(&w, 1, H160::from([0x88; 20]), 0));
		let info = dispatch_info(&call);
		assert_eq!(
			call.pre_dispatch_self_contained(&w.address, &info, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Future
			))),
			"in-block validation requires an exact nonce match"
		);
	});
}

#[test]
fn pre_dispatch_rejects_wrong_chain_id() {
	// HI-1: a transaction validly signed for another chain must not execute here.
	with_ext(|| {
		let w = pqc_wallet(13);
		fund(w.address, RICH);
		let tx = sign_tx(
			&w,
			&TxSpec {
				chain_id: 999,
				..Default::default()
			},
		);
		let call = call_of(tx);
		let info = dispatch_info(&call);
		match call.pre_dispatch_self_contained(&w.address, &info, 0) {
			Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(code)))) => {
				assert_eq!(code, fp_evm::TransactionValidationError::InvalidChainId as u8);
			}
			other => panic!("cross-chain replay must be rejected, got {other:?}"),
		}
	});
}

#[test]
fn pre_dispatch_rejects_insufficient_balance() {
	with_ext(|| {
		let w = pqc_wallet(14);
		// Enough to exist, nowhere near enough for gas_limit * max_fee + value.
		fund(w.address, 10);
		let call = call_of(signed_transfer(&w, 0, H160::from([0x99; 20]), 0));
		let info = dispatch_info(&call);
		assert_eq!(
			call.pre_dispatch_self_contained(&w.address, &info, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Payment
			))),
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// F. WASM-side forgery pin in pre_dispatch
// ─────────────────────────────────────────────────────────────────────────────
//
// During block import inside WASM the full composite verification is not re-run;
// `pre_dispatch_self_contained` instead pins `keccak(pub_key)[12..] == origin`.
// That pin is the only thing preventing a malicious block author from swapping in
// a different public key, so it gets dedicated coverage.

#[test]
fn pre_dispatch_pins_public_key_to_origin() {
	with_ext(|| {
		let w = pqc_wallet(15);
		let impostor = pqc_wallet(16);
		fund(w.address, RICH);
		fund(impostor.address, RICH);

		let call = call_of(signed_transfer(&w, 0, H160::from([0xAA; 20]), 0));
		let info = dispatch_info(&call);

		// Claiming a different origin than the public key hashes to must be rejected.
		match call.pre_dispatch_self_contained(&impostor.address, &info, 0) {
			Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(code)))) => {
				assert_eq!(
					code,
					fp_evm::TransactionValidationError::InvalidSignature as u8,
					"origin/pub_key mismatch must be rejected"
				);
			}
			other => panic!("forged origin must be rejected by the pin, got {other:?}"),
		}
	});
}

#[test]
fn pre_dispatch_rejects_malformed_sizes() {
	// The WASM-side structural gates, independent of `check_self_contained`.
	let cases = vec![
		("bad pub_key length", COMPOSITE_PK_SIZE + 1, COMPOSITE_SIG_SIZE),
		("bad signature length", COMPOSITE_PK_SIZE, COMPOSITE_SIG_SIZE - 1),
	];
	for (name, pk_len, sig_len) in cases {
		with_ext(|| {
			let tx = BlackChainTransaction {
				pub_key: vec![0x07; pk_len],
				pqc_signature: vec![0x09; sig_len],
				..sign_shape_only()
			};
			let origin = H160::from_slice(&sp_io::hashing::keccak_256(&vec![0x07u8; pk_len])[12..]);
			let call = call_of(tx);
			let info = dispatch_info(&call);
			match call.pre_dispatch_self_contained(&origin, &info, 0) {
				Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(code)))) => {
					assert_eq!(
						code,
						fp_evm::TransactionValidationError::InvalidSignature as u8,
						"{name}"
					);
				}
				other => panic!("{name}: expected rejection, got {other:?}"),
			}
		});
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// G. End-to-end dispatch — the PQC path actually executing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transact_blackchain_transfers_value_and_increments_nonce() {
	with_ext(|| {
		let w = pqc_wallet(17);
		let recipient = H160::from([0xBB; 20]);
		fund(w.address, RICH);

		let sender_before = balance_of(w.address);
		assert_eq!(balance_of(recipient), U256::zero());
		assert_eq!(nonce_of(w.address), U256::zero());

		let tx = signed_transfer(&w, 0, recipient, 12_345);
		assert_ok!(Ethereum::transact_blackchain(
			RawOrigin::EthereumTransaction(w.address).into(),
			tx
		));

		assert_eq!(
			balance_of(recipient),
			U256::from(12_345u64),
			"recipient must receive the transferred value"
		);
		assert_eq!(
			nonce_of(w.address),
			U256::one(),
			"sender nonce must advance exactly once"
		);
		assert!(
			balance_of(w.address) < sender_before - U256::from(12_345u64),
			"sender must also pay gas"
		);
	});
}

#[test]
fn transact_blackchain_emits_executed_event_and_stores_receipt() {
	with_ext(|| {
		let w = pqc_wallet(18);
		let recipient = H160::from([0xCC; 20]);
		fund(w.address, RICH);

		let tx = signed_transfer(&w, 0, recipient, 1);
		let expected_hash = Ethereum::blackchain_to_evm_transaction(&tx)
			.expect("derived tx")
			.hash();

		assert_ok!(Ethereum::transact_blackchain(
			RawOrigin::EthereumTransaction(w.address).into(),
			tx
		));

		// A receipt/status/transaction triple must be pending for this block.
		assert_eq!(crate::Pending::<Test>::count(), 1);
		let (_stored_tx, status, _receipt) =
			crate::Pending::<Test>::get(0).expect("pending entry recorded");
		assert_eq!(status.from, w.address, "status must record the PQC sender");
		assert_eq!(status.to, Some(recipient));
		assert_eq!(
			status.transaction_hash, expected_hash,
			"indexed hash must equal the derived EIP-1559 hash"
		);

		// And the Executed event must name the real sender.
		let found = System::events().iter().any(|r| {
			matches!(
				&r.event,
				RuntimeEvent::Ethereum(Event::Executed { from, to, transaction_hash, .. })
					if *from == w.address && *to == recipient && *transaction_hash == expected_hash
			)
		});
		assert!(found, "Executed event with the PQC sender must be emitted");
	});
}

#[test]
fn transact_blackchain_rejects_mismatched_origin() {
	// Dispatch trusts the self-contained origin but re-pins it with a cheap keccak;
	// a mismatch must abort rather than execute under the wrong account.
	with_ext(|| {
		let w = pqc_wallet(19);
		let impostor = pqc_wallet(20);
		fund(w.address, RICH);
		fund(impostor.address, RICH);

		let tx = signed_transfer(&w, 0, H160::from([0xDD; 20]), 1);
		assert!(
			Ethereum::transact_blackchain(
				RawOrigin::EthereumTransaction(impostor.address).into(),
				tx
			)
			.is_err(),
			"dispatch under a mismatched origin must fail"
		);
	});
}

#[test]
fn sequential_transactions_advance_nonce_monotonically() {
	with_ext(|| {
		let w = pqc_wallet(21);
		let recipient = H160::from([0xEE; 20]);
		fund(w.address, RICH);

		for n in 0..3u64 {
			assert_eq!(nonce_of(w.address), U256::from(n));
			let tx = signed_transfer(&w, n, recipient, 10);
			assert_ok!(Ethereum::transact_blackchain(
				RawOrigin::EthereumTransaction(w.address).into(),
				tx
			));
		}
		assert_eq!(nonce_of(w.address), U256::from(3u64));
		assert_eq!(balance_of(recipient), U256::from(30u64));
		assert_eq!(crate::Pending::<Test>::count(), 3);
	});
}

#[test]
fn pqc_contract_creation_deploys_code() {
	// Contract creation through the PQC path (`is_create = true`) — previously
	// untested end to end.
	with_ext(|| {
		let w = pqc_wallet(22);
		fund(w.address, RICH);

		// The mock restricts CREATE to an allow-list; authorise this PQC address so
		// the test exercises deployment rather than the unrelated origin filter.
		AllowedAddressesCreate::set(vec![w.address]);
		AllowedAddressesCreateInner::set(vec![w.address]);

		let bytecode = hex::decode(ERC20_CONTRACT_BYTECODE.trim_end()).expect("bytecode");
		let expected = contract_address(w.address, 0);

		let tx = sign_tx(
			&w,
			&TxSpec {
				nonce: 0,
				to: None, // create
				value: 0,
				input: bytecode,
				gas_limit: 1_000_000,
				..Default::default()
			},
		);
		assert_ok!(Ethereum::transact_blackchain(
			RawOrigin::EthereumTransaction(w.address).into(),
			tx
		));

		assert!(
			!pallet_evm::AccountCodes::<Test>::get(expected).is_empty(),
			"contract code must be deployed at the CREATE address"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// H. Determinism of the derived EIP-1559 transaction
// ─────────────────────────────────────────────────────────────────────────────
//
// `blackchain_to_evm_transaction` is shared by the pre-filter, pool validation,
// the STF gate, dispatch, `extrinsic_filter` and the RPC runtime API. If any two
// call sites could derive different bytes, validation and execution would disagree
// — which is exactly how the CR-1 replay window opened.

#[test]
fn derived_transaction_is_deterministic() {
	with_ext(|| {
		let w = pqc_wallet(23);
		let tx = signed_transfer(&w, 7, H160::from([0x12; 20]), 999);
		let a = Ethereum::blackchain_to_evm_transaction(&tx).expect("derived a");
		let b = Ethereum::blackchain_to_evm_transaction(&tx).expect("derived b");
		assert_eq!(a.hash(), b.hash(), "derivation must be deterministic");
		assert_eq!(a, b, "derived transactions must be byte-identical");
	});
}

#[test]
fn derived_transaction_preserves_execution_parameters() {
	with_ext(|| {
		let w = pqc_wallet(24);
		let to = H160::from([0x34; 20]);
		let tx = sign_tx(
			&w,
			&TxSpec {
				nonce: 5,
				to: Some(to),
				value: 4_242,
				gas_limit: 55_555,
				max_fee_per_gas: 7,
				max_priority_fee_per_gas: 3,
				input: vec![1, 2, 3],
				..Default::default()
			},
		);
		let derived = Ethereum::blackchain_to_evm_transaction(&tx).expect("derived");
		match derived {
			Transaction::EIP1559(t) => {
				assert_eq!(t.chain_id, CHAIN_ID);
				assert_eq!(t.nonce, U256::from(5u64));
				assert_eq!(t.value, U256::from(4_242u64));
				assert_eq!(t.gas_limit, U256::from(55_555u64));
				assert_eq!(t.max_fee_per_gas, U256::from(7u64));
				assert_eq!(t.max_priority_fee_per_gas, U256::from(3u64));
				assert_eq!(t.action, TransactionAction::Call(to));
				assert_eq!(t.input, vec![1, 2, 3]);
			}
			other => panic!("expected an EIP-1559 wrapper, got {other:?}"),
		}
	});
}

#[test]
fn distinct_signatures_produce_distinct_transaction_hashes() {
	// Replaces a previously vacuous test: two transactions with IDENTICAL execution
	// fields but different composite signatures must not collide, because r/s are
	// derived from keccak256(pqc_signature).
	with_ext(|| {
		let a = pqc_wallet(25);
		let b = pqc_wallet(26);
		let spec = TxSpec::default();
		let tx_a = sign_tx(&a, &spec);
		let tx_b = sign_tx(&b, &spec);
		assert_ne!(tx_a.pqc_signature, tx_b.pqc_signature);

		let ha = Ethereum::blackchain_to_evm_transaction(&tx_a).unwrap().hash();
		let hb = Ethereum::blackchain_to_evm_transaction(&tx_b).unwrap().hash();
		assert_ne!(ha, hb, "distinct signatures must yield distinct tx hashes");
	});
}

#[test]
fn derived_signature_components_are_nonzero_placeholders() {
	// r and s are non-cryptographic placeholders, but must still be structurally
	// valid (non-zero) or the EIP-1559 wrapper cannot be constructed.
	with_ext(|| {
		let w = pqc_wallet(27);
		let tx = signed_transfer(&w, 0, H160::from([0x56; 20]), 0);
		match Ethereum::blackchain_to_evm_transaction(&tx).expect("derived") {
			Transaction::EIP1559(t) => {
				assert_ne!(t.signature.r(), &H256::zero());
				assert_ne!(t.signature.s(), &H256::zero());
				assert_ne!(t.signature.r(), t.signature.s());
			}
			_ => panic!("expected EIP-1559"),
		}
	});
}

#[test]
fn create_and_call_transactions_derive_different_actions() {
	with_ext(|| {
		let w = pqc_wallet(28);
		let to = H160::from([0x78; 20]);
		let call_tx = sign_tx(
			&w,
			&TxSpec {
				to: Some(to),
				..Default::default()
			},
		);
		let create_tx = sign_tx(
			&w,
			&TxSpec {
				to: None,
				gas_limit: 100_000,
				..Default::default()
			},
		);
		match Ethereum::blackchain_to_evm_transaction(&call_tx).unwrap() {
			Transaction::EIP1559(t) => assert_eq!(t.action, TransactionAction::Call(to)),
			_ => panic!("expected EIP-1559"),
		}
		match Ethereum::blackchain_to_evm_transaction(&create_tx).unwrap() {
			Transaction::EIP1559(t) => assert_eq!(t.action, TransactionAction::Create),
			_ => panic!("expected EIP-1559"),
		}
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// I. Pool validation and mempool ordering
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_self_contained_accepts_a_ready_transaction() {
	with_ext(|| {
		let w = pqc_wallet(29);
		fund(w.address, RICH);
		let call = call_of(signed_transfer(&w, 0, H160::from([0x9A; 20]), 0));
		let info = dispatch_info(&call);
		let valid = call
			.validate_self_contained(&w.address, &info, 0)
			.expect("blackchain calls are self-contained")
			.expect("a funded, in-order transaction must be poolable");
		assert!(
			valid.requires.is_empty(),
			"an in-order transaction has no unmet dependency"
		);
		assert!(
			!valid.provides.is_empty(),
			"a poolable transaction must provide its (sender, nonce) tag"
		);
	});
}

#[test]
fn validate_self_contained_marks_nonce_gap_as_requiring_predecessor() {
	// Mempool ordering: a future nonce is legal in the pool but must declare the
	// dependency so it is only included after its predecessor.
	with_ext(|| {
		let w = pqc_wallet(30);
		fund(w.address, RICH);
		let call = call_of(signed_transfer(&w, 2, H160::from([0xAB; 20]), 0));
		let info = dispatch_info(&call);
		let valid = call
			.validate_self_contained(&w.address, &info, 0)
			.unwrap()
			.expect("a future nonce is poolable");
		assert!(
			!valid.requires.is_empty(),
			"a nonce gap must declare its predecessor dependency"
		);
	});
}

#[test]
fn validate_self_contained_rejects_stale_nonce_at_pool_admission() {
	with_ext(|| {
		use pallet_evm::AddressMapping;
		let w = pqc_wallet(31);
		fund(w.address, RICH);
		let account = <Test as pallet_evm::Config>::AddressMapping::into_account_id(w.address);
		frame_system::Account::<Test>::mutate(&account, |a| a.nonce = 5);

		let call = call_of(signed_transfer(&w, 0, H160::from([0xBC; 20]), 0));
		let info = dispatch_info(&call);
		assert_eq!(
			call.validate_self_contained(&w.address, &info, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Stale
			))),
			"already-spent nonces must not re-enter the pool"
		);
	});
}

#[test]
fn blackchain_calls_are_self_contained() {
	let w = pqc_wallet(32);
	let tx = signed_transfer(&w, 0, H160::from([0xCD; 20]), 0);
	assert!(call_of(tx).is_self_contained());
}
