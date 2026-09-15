// Unit tests for pallet-blackchain-sudo.
//
// These exercise the security-critical self-contained verification path with the
// REAL composite crypto (via the `blackchain-crypto-lib-rust` dev-dependency):
//   * a valid admin signature is accepted and recovers the admin address,
//   * a non-admin key is rejected by the cheap pre-filter (before verify),
//   * a tampered signature is rejected,
//   * the admin nonce is enforced (stale / future) and a full `sudo` dispatch
//     runs the inner call with Root and bumps the nonce.

use crate as pallet_blackchain_sudo;
use crate::{RawOrigin, SUDO_DOMAIN_TAG};
use blackchain_crypto_lib_rust::{sign_message, BlackChainPrivateKey};
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types};
use scale_codec::Encode;
use sp_core::H160;
use sp_runtime::{
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		BlackchainSudo: pallet_blackchain_sudo,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

parameter_types! {
	pub const TestChainId: u64 = 42;
}

impl pallet_blackchain_sudo::Config for Test {
	type RuntimeCall = RuntimeCall;
	type ChainId = TestChainId;
}

// A deterministic composite keypair (no OS randomness needed).
fn admin_key(seed_byte: u8) -> BlackChainPrivateKey {
	let seed = [seed_byte; 64];
	let (k, _) = BlackChainPrivateKey::generate(&seed).expect("keygen");
	k
}

fn address_of(k: &BlackChainPrivateKey) -> H160 {
	let pk = k.public_key().to_bytes();
	H160::from_slice(&sp_io::hashing::keccak_256(&pk)[12..])
}

// A harmless inner call to authorise.
fn inner_call() -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark {
		remark: alloc_vec(),
	})
}

fn alloc_vec() -> Vec<u8> {
	vec![1, 2, 3, 4]
}

// Build the exact payload the pallet signs, then a signed `sudo` call.
fn signed_sudo_call(
	k: &BlackChainPrivateKey,
	inner: RuntimeCall,
	nonce: u64,
	tamper: bool,
) -> crate::Call<Test> {
	let mut payload = Vec::new();
	payload.extend_from_slice(SUDO_DOMAIN_TAG);
	payload.extend_from_slice(&TestChainId::get().to_le_bytes());
	payload.extend_from_slice(&nonce.to_le_bytes());
	payload.extend_from_slice(&inner.encode());

	let mut signature = sign_message(&payload, k).expect("sign");
	if tamper {
		signature[0] ^= 0xFF;
	}
	let pub_key = k.public_key().to_bytes();
	crate::Call::sudo {
		call: Box::new(inner),
		nonce,
		pub_key,
		signature,
	}
}

fn new_test_ext(admin: Option<H160>) -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	let mut ext: sp_io::TestExternalities = t.into();
	ext.execute_with(|| {
		if let Some(a) = admin {
			crate::AdminKey::<Test>::put(a);
		}
	});
	ext
}

#[test]
fn valid_admin_signature_is_accepted() {
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let call = signed_sudo_call(&k, inner_call(), 0, false);
		match call.check_self_contained() {
			Some(Ok(recovered)) => assert_eq!(recovered, admin),
			other => panic!("valid admin sig must be accepted, got {:?}", other.is_some()),
		}
	});
}

#[test]
fn non_admin_key_is_rejected_before_verify() {
	// AdminKey is a DIFFERENT address than the signer — the cheap pre-filter must
	// reject with BadSigner, without running the expensive verify.
	let signer = admin_key(7);
	let other_admin = address_of(&admin_key(9));
	new_test_ext(Some(other_admin)).execute_with(|| {
		let call = signed_sudo_call(&signer, inner_call(), 0, false);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::BadSigner
			)))
		);
	});
}

#[test]
fn tampered_signature_is_rejected() {
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let call = signed_sudo_call(&k, inner_call(), 0, true);
		// Signer address (from pub_key) still matches AdminKey, so the pre-filter
		// passes; the composite verify then fails → Custom(0).
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Custom(0)
			)))
		);
	});
}

#[test]
fn pre_dispatch_enforces_admin_nonce() {
	let k = admin_key(7);
	let admin = address_of(&k);
	let di = frame_support::dispatch::DispatchInfo::default();
	new_test_ext(Some(admin)).execute_with(|| {
		// Current AdminNonce is 0.
		let ok = signed_sudo_call(&k, inner_call(), 0, false);
		assert!(matches!(
			ok.pre_dispatch_self_contained(&admin, &di, 0),
			Some(Ok(()))
		));

		// Future nonce (1) rejected.
		let future = signed_sudo_call(&k, inner_call(), 1, false);
		assert_eq!(
			future.pre_dispatch_self_contained(&admin, &di, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Future
			)))
		);

		// After the admin has already used nonce 0..=2, reusing nonce 0 is stale.
		crate::AdminNonce::<Test>::put(3);
		let stale = signed_sudo_call(&k, inner_call(), 0, false);
		assert_eq!(
			stale.pre_dispatch_self_contained(&admin, &di, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Stale
			)))
		);
	});
}

#[test]
fn sudo_dispatch_runs_inner_as_root_and_bumps_nonce() {
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		// Inner call requires Root: `System::set_storage`.
		let key = b"pqc_sudo_test_key".to_vec();
		let val = b"root-was-here".to_vec();
		let inner = RuntimeCall::System(frame_system::Call::set_storage {
			items: vec![(key.clone(), val.clone())],
		});
		assert_eq!(crate::AdminNonce::<Test>::get(), 0);

		assert_ok!(BlackchainSudo::sudo(
			RawOrigin::BlackchainAdmin(admin).into(),
			Box::new(inner),
			0,
			k.public_key().to_bytes(),
			vec![0u8; crate::COMPOSITE_SIG_SIZE], // signature unused in dispatch (origin is trusted)
		));

		// Inner Root call took effect and the admin nonce advanced.
		assert_eq!(sp_io::storage::get(&key).map(|v| v.to_vec()), Some(val));
		assert_eq!(crate::AdminNonce::<Test>::get(), 1);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload binding: domain tag, chain id and nonce are all inside the signature
// ─────────────────────────────────────────────────────────────────────────────

/// Signs an arbitrary payload and wraps it as a `sudo` call — used to prove that a
/// signature over anything other than the canonical payload is rejected.
fn sudo_call_with_payload(
	k: &BlackChainPrivateKey,
	inner: RuntimeCall,
	declared_nonce: u64,
	payload: &[u8],
) -> crate::Call<Test> {
	let signature = sign_message(payload, k).expect("sign");
	crate::Call::sudo {
		call: Box::new(inner),
		nonce: declared_nonce,
		pub_key: k.public_key().to_bytes(),
		signature,
	}
}

fn canonical_payload(chain_id: u64, nonce: u64, inner: &RuntimeCall) -> Vec<u8> {
	let mut p = Vec::new();
	p.extend_from_slice(SUDO_DOMAIN_TAG);
	p.extend_from_slice(&chain_id.to_le_bytes());
	p.extend_from_slice(&nonce.to_le_bytes());
	p.extend_from_slice(&inner.encode());
	p
}

#[test]
fn signature_for_another_chain_is_rejected() {
	// Cross-chain replay of a privileged call: an admin signature produced for a
	// different chain id must not authorise anything here.
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let inner = inner_call();
		let foreign = canonical_payload(999, 0, &inner);
		let call = sudo_call_with_payload(&k, inner, 0, &foreign);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Custom(0)
			))),
			"a sudo signature bound to another chain must not verify here"
		);
	});
}

#[test]
fn signature_for_another_nonce_is_rejected() {
	// Prevents lifting a signature from one admin action onto a later slot.
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let inner = inner_call();
		let payload_for_nonce_5 = canonical_payload(TestChainId::get(), 5, &inner);
		// Declared nonce (0) disagrees with the signed nonce (5).
		let call = sudo_call_with_payload(&k, inner, 0, &payload_for_nonce_5);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Custom(0)
			))),
			"the nonce is inside the signed payload and must match the declared nonce"
		);
	});
}

#[test]
fn signature_over_a_different_call_is_rejected() {
	// The whole point of the scheme: the authorised call cannot be swapped.
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let authorised = inner_call();
		let payload = canonical_payload(TestChainId::get(), 0, &authorised);

		let substituted = RuntimeCall::System(frame_system::Call::set_storage {
			items: vec![(b"attacker".to_vec(), b"owned".to_vec())],
		});
		let call = sudo_call_with_payload(&k, substituted, 0, &payload);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Custom(0)
			))),
			"substituting the inner call must invalidate the admin signature"
		);
	});
}

#[test]
fn signature_without_the_domain_tag_is_rejected() {
	// Domain separation stops a signature made for some other purpose (e.g. a plain
	// transaction) from being replayed as an admin authorisation.
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let inner = inner_call();
		let mut undomained = Vec::new();
		undomained.extend_from_slice(&TestChainId::get().to_le_bytes());
		undomained.extend_from_slice(&0u64.to_le_bytes());
		undomained.extend_from_slice(&inner.encode());
		let call = sudo_call_with_payload(&k, inner, 0, &undomained);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Custom(0)
			))),
			"payloads missing the domain tag must not authorise sudo"
		);
	});
}

#[test]
fn signing_payload_is_exactly_the_documented_format() {
	// Pins the wire format so the off-chain signer and the runtime cannot drift.
	new_test_ext(None).execute_with(|| {
		let inner = inner_call();
		let built = BlackchainSudo::sudo_signing_payload(&inner, 3);
		assert_eq!(built, canonical_payload(TestChainId::get(), 3, &inner));
		assert!(built.starts_with(SUDO_DOMAIN_TAG));
		assert_eq!(SUDO_DOMAIN_TAG, b"BLACKCHAIN_SUDO_V1");
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural gates and admin-key configuration
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn malformed_key_or_signature_sizes_are_rejected() {
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let inner = inner_call();
		let payload = canonical_payload(TestChainId::get(), 0, &inner);
		let good_sig = sign_message(&payload, &k).expect("sign");

		let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
			("empty pub_key", vec![], good_sig.clone()),
			("empty signature", k.public_key().to_bytes(), vec![]),
			(
				"short signature",
				k.public_key().to_bytes(),
				good_sig[..good_sig.len() - 1].to_vec(),
			),
			("padded signature", k.public_key().to_bytes(), {
				let mut s = good_sig.clone();
				s.push(0);
				s
			}),
		];

		for (name, pub_key, signature) in cases {
			let call = crate::Call::<Test>::sudo {
				call: Box::new(inner.clone()),
				nonce: 0,
				pub_key,
				signature,
			};
			assert_eq!(
				call.check_self_contained(),
				Some(Err(TransactionValidityError::Invalid(
					InvalidTransaction::Custom(0)
				))),
				"{name} must be rejected by the size gate"
			);
		}
	});
}

#[test]
fn admin_path_is_disabled_when_no_key_is_configured() {
	// `AdminKey = None` must make the privileged path inert, not open.
	let k = admin_key(7);
	new_test_ext(None).execute_with(|| {
		let call = signed_sudo_call(&k, inner_call(), 0, false);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::BadSigner
			))),
			"with no admin key configured, no signature may authorise Root"
		);
	});
}

#[test]
fn sudo_call_is_self_contained() {
	let k = admin_key(7);
	assert!(signed_sudo_call(&k, inner_call(), 0, false).is_self_contained());
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_self_contained_accepts_the_current_nonce() {
	let k = admin_key(7);
	let admin = address_of(&k);
	let di = frame_support::dispatch::DispatchInfo::default();
	new_test_ext(Some(admin)).execute_with(|| {
		let call = signed_sudo_call(&k, inner_call(), 0, false);
		let valid = call
			.validate_self_contained(&admin, &di, 0)
			.expect("sudo is self-contained")
			.expect("current nonce must be poolable");
		assert!(valid.requires.is_empty());
		assert!(!valid.provides.is_empty());
	});
}

#[test]
fn validate_self_contained_declares_dependency_for_a_nonce_gap() {
	let k = admin_key(7);
	let admin = address_of(&k);
	let di = frame_support::dispatch::DispatchInfo::default();
	new_test_ext(Some(admin)).execute_with(|| {
		let call = signed_sudo_call(&k, inner_call(), 2, false);
		let valid = call
			.validate_self_contained(&admin, &di, 0)
			.unwrap()
			.expect("a future admin nonce is poolable");
		assert!(
			!valid.requires.is_empty(),
			"an admin nonce gap must declare its predecessor"
		);
	});
}

#[test]
fn validate_self_contained_rejects_stale_and_non_admin() {
	let k = admin_key(7);
	let admin = address_of(&k);
	let outsider = address_of(&admin_key(9));
	let di = frame_support::dispatch::DispatchInfo::default();
	new_test_ext(Some(admin)).execute_with(|| {
		crate::AdminNonce::<Test>::put(4);
		let stale = signed_sudo_call(&k, inner_call(), 0, false);
		assert_eq!(
			stale.validate_self_contained(&admin, &di, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::Stale
			))),
		);

		let call = signed_sudo_call(&k, inner_call(), 4, false);
		assert_eq!(
			call.validate_self_contained(&outsider, &di, 0),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::BadSigner
			))),
			"pool validation must also pin the origin to the configured admin"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin key rotation — the recovery path if the admin key is ever compromised
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn set_key_requires_root() {
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		let new_admin = address_of(&admin_key(9));
		// A verified admin origin is NOT Root: rotation must go through `sudo`.
		assert!(BlackchainSudo::set_key(
			RawOrigin::BlackchainAdmin(admin).into(),
			new_admin
		)
		.is_err());
		assert!(
			BlackchainSudo::set_key(frame_system::RawOrigin::None.into(), new_admin).is_err(),
			"unsigned origins must not rotate the admin key"
		);
		assert_eq!(crate::AdminKey::<Test>::get(), Some(admin));
	});
}

#[test]
fn admin_can_rotate_its_own_key_through_sudo() {
	// End-to-end key rotation: the current admin PQC-signs `sudo(set_key(new))`.
	let old = admin_key(7);
	let new = admin_key(9);
	let old_addr = address_of(&old);
	let new_addr = address_of(&new);

	new_test_ext(Some(old_addr)).execute_with(|| {
		System::set_block_number(1);
		let inner = RuntimeCall::BlackchainSudo(crate::Call::set_key { new: new_addr });

		assert_ok!(BlackchainSudo::sudo(
			RawOrigin::BlackchainAdmin(old_addr).into(),
			Box::new(inner),
			0,
			old.public_key().to_bytes(),
			vec![0u8; crate::COMPOSITE_SIG_SIZE],
		));

		assert_eq!(
			crate::AdminKey::<Test>::get(),
			Some(new_addr),
			"the admin key must be rotated"
		);
		assert!(
			System::events().iter().any(|r| matches!(
				&r.event,
				RuntimeEvent::BlackchainSudo(crate::Event::AdminKeyChanged { old, new })
					if *old == Some(old_addr) && *new == new_addr
			)),
			"AdminKeyChanged must be emitted"
		);
	});
}

#[test]
fn rotated_out_key_can_no_longer_authorise() {
	// The security property that makes rotation worth having.
	let old = admin_key(7);
	let new = admin_key(9);
	let old_addr = address_of(&old);
	let new_addr = address_of(&new);

	new_test_ext(Some(old_addr)).execute_with(|| {
		crate::AdminKey::<Test>::put(new_addr);

		let call = signed_sudo_call(&old, inner_call(), 0, false);
		assert_eq!(
			call.check_self_contained(),
			Some(Err(TransactionValidityError::Invalid(
				InvalidTransaction::BadSigner
			))),
			"the previous admin key must lose all authority after rotation"
		);

		// ...and the new key works.
		let new_call = signed_sudo_call(&new, inner_call(), 0, false);
		assert!(matches!(new_call.check_self_contained(), Some(Ok(addr)) if addr == new_addr));
	});
}

#[test]
fn sudo_emits_event_and_reports_inner_failure_without_aborting() {
	// A failing privileged call must consume its nonce and be reported, rather than
	// silently rolling back and leaving the nonce replayable.
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		System::set_block_number(1);
		// `set_key` under a non-Root origin fails inside the wrapper.
		let failing = RuntimeCall::System(frame_system::Call::kill_storage {
			keys: vec![b"nonexistent".to_vec()],
		});
		assert_ok!(BlackchainSudo::sudo(
			RawOrigin::BlackchainAdmin(admin).into(),
			Box::new(failing),
			0,
			k.public_key().to_bytes(),
			vec![0u8; crate::COMPOSITE_SIG_SIZE],
		));
		assert_eq!(
			crate::AdminNonce::<Test>::get(),
			1,
			"the admin nonce must advance so the authorisation cannot be replayed"
		);
		assert!(System::events().iter().any(|r| matches!(
			&r.event,
			RuntimeEvent::BlackchainSudo(crate::Event::Sudid { admin: a, nonce, .. })
				if *a == admin && *nonce == 0
		)));
	});
}

#[test]
fn non_admin_origin_cannot_dispatch_sudo() {
	let k = admin_key(7);
	let admin = address_of(&k);
	let outsider = address_of(&admin_key(9));
	new_test_ext(Some(admin)).execute_with(|| {
		assert_noop!(
			BlackchainSudo::sudo(
				RawOrigin::BlackchainAdmin(outsider).into(),
				Box::new(inner_call()),
				0,
				k.public_key().to_bytes(),
				vec![0u8; crate::COMPOSITE_SIG_SIZE],
			),
			crate::Error::<Test>::RequireAdmin
		);
		assert_noop!(
			BlackchainSudo::sudo(
				frame_system::RawOrigin::Root.into(),
				Box::new(inner_call()),
				0,
				k.public_key().to_bytes(),
				vec![0u8; crate::COMPOSITE_SIG_SIZE],
			),
			crate::Error::<Test>::RequireAdmin
		);
	});
}

#[test]
fn sudo_rejects_stale_nonce_at_dispatch() {
	let k = admin_key(7);
	let admin = address_of(&k);
	new_test_ext(Some(admin)).execute_with(|| {
		crate::AdminNonce::<Test>::put(5);
		let inner = RuntimeCall::System(frame_system::Call::remark { remark: alloc_vec() });
		assert_noop!(
			BlackchainSudo::sudo(
				RawOrigin::BlackchainAdmin(admin).into(),
				Box::new(inner),
				0, // stale
				k.public_key().to_bytes(),
				vec![0u8; crate::COMPOSITE_SIG_SIZE],
			),
			crate::Error::<Test>::BadNonce
		);
	});
}
