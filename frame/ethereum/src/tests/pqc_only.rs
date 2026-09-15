// frame/ethereum/src/tests/pqc_only.rs
//
// Proves the chain is PQC-ONLY at the signature-verification layer.
//
// This chain deliberately removes secp256k1 ECDSA as an authentication mechanism:
// `Pallet::recover_signer` returns `None` for every classic Ethereum transaction
// variant, so a classic transaction can never produce a valid origin no matter how
// correctly it is signed.
//
// These tests assert that property POSITIVELY — with genuinely valid ECDSA
// signatures — rather than leaving it as an implicit consequence. They are the
// reason the upstream classic-transaction tests in `legacy.rs` / `eip1559.rs` /
// `eip2930.rs` / `eip7702.rs` are marked `#[ignore]`: those tests assert
// behaviour (nonce/gas/chain-id handling of ECDSA transactions) that is
// unreachable here, and their PQC equivalents live in `blackchain.rs`.
//
// If ECDSA were ever intentionally re-enabled, these tests are what should fail
// first.

use super::*;

/// The `InvalidTransaction::Custom` code the pallet emits when a signature cannot
/// be recovered. Pinned explicitly so an accidental renumbering is caught.
const INVALID_SIGNATURE: u8 = fp_evm::TransactionValidationError::InvalidSignature as u8;

fn expect_signature_rejected(call: crate::Call<Test>, variant: &str) {
	match call.check_self_contained() {
		Some(Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(code)))) => {
			assert_eq!(
				code, INVALID_SIGNATURE,
				"{variant}: classic ECDSA must be rejected as InvalidSignature"
			);
		}
		Some(Ok(addr)) => panic!(
			"{variant}: classic ECDSA transaction was ACCEPTED (recovered {addr:?}) — \
			 the chain is no longer PQC-only!"
		),
		other => panic!("{variant}: unexpected result {other:?}"),
	}
}

#[test]
fn legacy_ecdsa_transaction_is_rejected() {
	let (pairs, mut ext) = new_test_ext(1);
	let alice = &pairs[0];
	ext.execute_with(|| {
		let tx = LegacyUnsignedTransaction {
			nonce: U256::zero(),
			gas_price: U256::from(1),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(H160::from([0x11; 20])),
			value: U256::zero(),
			input: vec![],
		}
		.sign(&alice.private_key);
		expect_signature_rejected(crate::Call::<Test>::transact { transaction: tx }, "legacy");
	});
}

#[test]
fn eip2930_ecdsa_transaction_is_rejected() {
	let (pairs, mut ext) = new_test_ext(1);
	let alice = &pairs[0];
	ext.execute_with(|| {
		let tx = EIP2930UnsignedTransaction {
			nonce: U256::zero(),
			gas_price: U256::from(1),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(H160::from([0x22; 20])),
			value: U256::zero(),
			input: vec![],
		}
		.sign(&alice.private_key, None);
		expect_signature_rejected(crate::Call::<Test>::transact { transaction: tx }, "eip2930");
	});
}

#[test]
fn eip1559_ecdsa_transaction_is_rejected() {
	let (pairs, mut ext) = new_test_ext(1);
	let alice = &pairs[0];
	ext.execute_with(|| {
		let tx = EIP1559UnsignedTransaction {
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::from(1),
			max_fee_per_gas: U256::from(1),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(H160::from([0x33; 20])),
			value: U256::zero(),
			input: vec![],
		}
		.sign(&alice.private_key, None);
		expect_signature_rejected(crate::Call::<Test>::transact { transaction: tx }, "eip1559");
	});
}

#[test]
fn eip7702_ecdsa_transaction_is_rejected() {
	let (pairs, mut ext) = new_test_ext(1);
	let alice = &pairs[0];
	ext.execute_with(|| {
		let tx = EIP7702UnsignedTransaction {
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::from(1),
			max_fee_per_gas: U256::from(1),
			gas_limit: U256::from(21_000),
			destination: TransactionAction::Call(H160::from([0x44; 20])),
			value: U256::zero(),
			data: vec![],
			authorization_list: vec![],
		}
		.sign(&alice.private_key, None);
		expect_signature_rejected(crate::Call::<Test>::transact { transaction: tx }, "eip7702");
	});
}

#[test]
fn classic_transactions_are_still_recognised_as_self_contained() {
	// Rejection must happen at signature recovery, NOT by the call being treated as
	// a non-self-contained (and therefore unsigned/bare) extrinsic — that would be a
	// far more dangerous failure mode.
	let (pairs, mut ext) = new_test_ext(1);
	let alice = &pairs[0];
	ext.execute_with(|| {
		let tx = LegacyUnsignedTransaction {
			nonce: U256::zero(),
			gas_price: U256::from(1),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(H160::from([0x55; 20])),
			value: U256::zero(),
			input: vec![],
		}
		.sign(&alice.private_key);
		let call = crate::Call::<Test>::transact { transaction: tx };
		assert!(
			call.is_self_contained(),
			"classic transact must remain self-contained so it is rejected at \
			 signature recovery rather than bypassing the check entirely"
		);
	});
}

#[test]
fn recover_signer_returns_none_for_every_classic_variant() {
	// Direct assertion on the primitive the whole PQC-only property rests on.
	let (pairs, mut ext) = new_test_ext(1);
	let alice = &pairs[0];
	ext.execute_with(|| {
		let legacy = LegacyUnsignedTransaction {
			nonce: U256::zero(),
			gas_price: U256::from(1),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(H160::from([0x66; 20])),
			value: U256::zero(),
			input: vec![],
		}
		.sign(&alice.private_key);
		let eip1559 = EIP1559UnsignedTransaction {
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::from(1),
			max_fee_per_gas: U256::from(1),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(H160::from([0x77; 20])),
			value: U256::zero(),
			input: vec![],
		}
		.sign(&alice.private_key, None);

		for (name, tx) in [("legacy", legacy), ("eip1559", eip1559)] {
			assert!(
				Ethereum::recover_signer(&tx).is_none(),
				"{name}: recover_signer must not resolve a classic ECDSA sender"
			);
		}
	});
}
