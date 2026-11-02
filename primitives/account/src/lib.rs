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
#![warn(unused_crate_dependencies)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

// The host-function bridge is referenced only from the no_std (WASM) verification
// path; mark it used under std so `unused_crate_dependencies` stays quiet there.
#[cfg(feature = "std")]
use pallet_ethereum_blackchain_hf as _;

use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
// Substrate
use sp_core::{crypto::AccountId32, ecdsa, RuntimeDebug, H160, H256};
use sp_io::hashing::keccak_256;
use sp_runtime::MultiSignature;

// Polkadot / XCM
use xcm::latest::{Junction, Location};

/// A fully Ethereum-compatible `AccountId`.
/// Conforms to H160 address and ECDSA key standards.
/// Alternative to H256->H160 mapping.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash)]
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub struct AccountId20(pub [u8; 20]);

#[cfg(feature = "serde")]
impl_serde::impl_fixed_hash_serde!(AccountId20, 20);

#[cfg(feature = "std")]
impl std::str::FromStr for AccountId20 {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		H160::from_str(s)
			.map(Into::into)
			.map_err(|_| "invalid hex address.")
	}
}

impl fmt::Display for AccountId20 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let address = hex::encode(self.0).trim_start_matches("0x").to_lowercase();
		let address_hash = hex::encode(keccak_256(address.as_bytes()));

		let checksum: String =
			address
				.char_indices()
				.fold(String::from("0x"), |mut acc, (index, address_char)| {
					let n = u16::from_str_radix(&address_hash[index..index + 1], 16)
						.expect("Keccak256 hashed; qed");

					if n > 7 {
						// make char uppercase if ith character is 9..f
						acc.push_str(&address_char.to_uppercase().to_string())
					} else {
						// already lowercased
						acc.push(address_char)
					}

					acc
				});
		write!(f, "{checksum}")
	}
}

impl fmt::Debug for AccountId20 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?}", H160(self.0))
	}
}

impl From<[u8; 20]> for AccountId20 {
	fn from(bytes: [u8; 20]) -> Self {
		Self(bytes)
	}
}

impl<'a> TryFrom<&'a [u8]> for AccountId20 {
	type Error = ();
	fn try_from(x: &'a [u8]) -> Result<AccountId20, ()> {
		if x.len() == 20 {
			let mut data = [0; 20];
			data.copy_from_slice(x);
			Ok(AccountId20(data))
		} else {
			Err(())
		}
	}
}

impl From<AccountId20> for [u8; 20] {
	fn from(val: AccountId20) -> Self {
		val.0
	}
}

impl From<H160> for AccountId20 {
	fn from(h160: H160) -> Self {
		Self(h160.0)
	}
}

impl From<AccountId20> for H160 {
	fn from(val: AccountId20) -> Self {
		H160(val.0)
	}
}

impl AsRef<[u8]> for AccountId20 {
	fn as_ref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl AsMut<[u8]> for AccountId20 {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0[..]
	}
}

impl AsRef<[u8; 20]> for AccountId20 {
	fn as_ref(&self) -> &[u8; 20] {
		&self.0
	}
}

impl AsMut<[u8; 20]> for AccountId20 {
	fn as_mut(&mut self) -> &mut [u8; 20] {
		&mut self.0
	}
}

impl From<ecdsa::Public> for AccountId20 {
	fn from(pk: ecdsa::Public) -> Self {
		let decompressed = libsecp256k1::PublicKey::parse_compressed(&pk.0)
			.expect("Wrong compressed public key provided")
			.serialize();
		let mut m = [0u8; 64];
		m.copy_from_slice(&decompressed[1..65]);
		let account = H160::from(H256::from(keccak_256(&m)));
		Self(account.into())
	}
}

impl From<[u8; 32]> for AccountId20 {
	fn from(bytes: [u8; 32]) -> Self {
		let mut buffer = [0u8; 20];
		buffer.copy_from_slice(&bytes[..20]);
		Self(buffer)
	}
}

impl From<AccountId32> for AccountId20 {
	fn from(account: AccountId32) -> Self {
		let bytes: &[u8; 32] = account.as_ref();
		Self::from(*bytes)
	}
}

impl From<AccountId20> for Location {
	fn from(id: AccountId20) -> Self {
		Junction::AccountKey20 {
			network: None,
			key: id.into(),
		}
		.into()
	}
}

#[derive(Clone, Eq, PartialEq)]
#[derive(
	RuntimeDebug,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EthereumSignature(ecdsa::Signature);

impl sp_runtime::traits::Verify for EthereumSignature {
	type Signer = EthereumSigner;
	fn verify<L: sp_runtime::traits::Lazy<[u8]>>(&self, _msg: L, _signer: &AccountId20) -> bool {
		// ── BlackChain is a PQC-only chain ──────────────────────────────────
		// Classical secp256k1 ECDSA is broken by a sufficiently large quantum
		// computer (Shor's algorithm), so it must NOT be a valid authentication
		// mechanism anywhere on the network.
		//
		// This `Verify` impl is what authenticates *signed Substrate extrinsics*
		// (the `(address, signature, extra)` format used to call pallets such as
		// Balances or Sudo directly). Returning `false` unconditionally makes
		// every such extrinsic fail signature checking with `BadProof`, so the
		// only ways to authorise state changes are:

		// NOTE: this deliberately disables the classical signed-extrinsic path.
		// Any admin capability that used to rely on a signed extrinsic (e.g.
		// `pallet_sudo`) must instead be driven through the PQC path.
		false
	}
}

impl From<MultiSignature> for EthereumSignature {
	fn from(signature: MultiSignature) -> Self {
		match signature {
			MultiSignature::Ed25519(_) => {
				panic!("Ed25519 not supported for EthereumSignature")
			}
			MultiSignature::Sr25519(_) => {
				panic!("Sr25519 not supported for EthereumSignature")
			}
			MultiSignature::Ecdsa(sig) => Self(sig),
			MultiSignature::Eth(sig) => Self(ecdsa::Signature::from(sig.0)),
		}
	}
}

impl EthereumSignature {
	pub fn new(s: ecdsa::Signature) -> Self {
		Self(s)
	}
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[derive(RuntimeDebug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[repr(transparent)]
pub struct EthereumSigner([u8; 20]);

impl From<[u8; 20]> for EthereumSigner {
	fn from(x: [u8; 20]) -> Self {
		EthereumSigner(x)
	}
}

impl sp_runtime::traits::IdentifyAccount for EthereumSigner {
	type AccountId = AccountId20;
	fn into_account(self) -> AccountId20 {
		AccountId20(self.0)
	}
}

impl fmt::Display for EthereumSigner {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		write!(fmt, "{:?}", H160::from(self.0))
	}
}

impl From<ecdsa::Public> for EthereumSigner {
	fn from(pk: ecdsa::Public) -> Self {
		let decompressed = libsecp256k1::PublicKey::parse_compressed(&pk.0)
			.expect("Wrong compressed public key provided")
			.serialize();
		let mut m = [0u8; 64];
		m.copy_from_slice(&decompressed[1..65]);
		let account = H160::from(H256::from(keccak_256(&m)));
		EthereumSigner(account.into())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-quantum signed-extrinsic authentication
//
// `PqcSignature` is the runtime's `Signature` type on a BlackChain network. Making
// it the runtime signature puts EVERY signed Substrate extrinsic — any pallet call
// (Balances, System, future pallets) — behind the composite hybrid verifier at the
// single `Verify` choke point, with no per-pallet code. Unlike ECDSA, a PQC
// signature carries its own public key (verification cannot recover it), and the
// account is `keccak256(pub_key)[12..]` — byte-for-byte the EVM H160, so one key is
// one account across the Substrate and EVM sides.
// ─────────────────────────────────────────────────────────────────────────────

/// Composite public key size: ML-DSA-87-pk(2592) + P521-pk(133) + Ed448-pk(57).
pub const COMPOSITE_PK_SIZE: usize = 2782;
/// Composite signature size: ML-DSA-87-sig(4627) + P521-sig(132) + Ed448-sig(114).
pub const COMPOSITE_SIG_SIZE: usize = 4873;

/// Domain-separation tag folded into every signed-extrinsic payload, keeping this
/// path's signatures disjoint from the EVM / admin / message paths. Bumping the
/// version invalidates all previously-produced extrinsic signatures.
pub const EXTRINSIC_DOMAIN_TAG: &[u8] = b"BLACKCHAIN_EXTRINSIC_V1";

/// A composite post-quantum signature over a signed Substrate extrinsic:
/// `[ML-DSA-87 ‖ P-521 ‖ Ed448]` plus the composite public key it was made with.
#[derive(Clone, Eq, PartialEq)]
#[derive(RuntimeDebug, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PqcSignature {
	/// Composite public key (`COMPOSITE_PK_SIZE` bytes).
	pub pub_key: Vec<u8>,
	/// Composite signature (`COMPOSITE_SIG_SIZE` bytes).
	pub signature: Vec<u8>,
}

impl PqcSignature {
	pub fn new(pub_key: Vec<u8>, signature: Vec<u8>) -> Self {
		Self { pub_key, signature }
	}

	/// Verify the composite signature over `message` and recover the signer, via
	/// the native crypto (std) or the `verify_pqc_message` host function (WASM).
	fn recover(message: &[u8], signature: &[u8], pub_key: &[u8]) -> Option<AccountId20> {
		#[cfg(feature = "std")]
		{
			fp_blackchain_crypto::verify_message(message, signature, pub_key)
				.ok()
				.map(AccountId20)
		}
		#[cfg(not(feature = "std"))]
		{
			use pallet_ethereum_blackchain_hf::blackchain_crypto;
			let out = blackchain_crypto::verify_pqc_message(
				message.to_vec(),
				signature.to_vec(),
				pub_key.to_vec(),
			);
			if out.len() == 20 {
				let mut a = [0u8; 20];
				a.copy_from_slice(&out);
				Some(AccountId20(a))
			} else {
				None
			}
		}
	}
}

impl sp_runtime::traits::Verify for PqcSignature {
	type Signer = PqcSigner;

	fn verify<L: sp_runtime::traits::Lazy<[u8]>>(
		&self,
		mut msg: L,
		signer: &AccountId20,
	) -> bool {
		// Cheap structural pre-check before the ~1.6 ms verify.
		if self.pub_key.len() != COMPOSITE_PK_SIZE || self.signature.len() != COMPOSITE_SIG_SIZE {
			return false;
		}
		// Domain-separate the signed payload so an extrinsic signature can never be
		// valid on another path.
		let payload = msg.get();
		let mut message = Vec::with_capacity(EXTRINSIC_DOMAIN_TAG.len() + payload.len());
		message.extend_from_slice(EXTRINSIC_DOMAIN_TAG);
		message.extend_from_slice(payload);

		match Self::recover(&message, &self.signature, &self.pub_key) {
			Some(recovered) => &recovered == signer,
			None => false,
		}
	}
}

/// Signer side of [`PqcSignature`]: carries the recovered 20-byte address and
/// resolves it to the runtime `AccountId` (`AccountId20`). The runtime derives its
/// `AccountId` from this, so switching the signature type keeps the address rule
/// (`keccak256(pub_key)[12..]`) consistent everywhere with no hard-coding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[derive(RuntimeDebug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[repr(transparent)]
pub struct PqcSigner([u8; 20]);

impl From<[u8; 20]> for PqcSigner {
	fn from(x: [u8; 20]) -> Self {
		PqcSigner(x)
	}
}

impl sp_runtime::traits::IdentifyAccount for PqcSigner {
	type AccountId = AccountId20;
	fn into_account(self) -> AccountId20 {
		AccountId20(self.0)
	}
}

impl fmt::Display for PqcSigner {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		write!(fmt, "{:?}", H160::from(self.0))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::{ecdsa, Pair, H256};
	use sp_runtime::traits::IdentifyAccount;

	#[test]
	fn test_derive_from_secret_key() {
		let sk = hex::decode("eb3d6b0b0c794f6fd8964b4a28df99d4baa5f9c8d33603c4cc62504daa259358")
			.unwrap();
		let hex_acc: [u8; 20] = hex::decode("98fa2838ee6471ae87135880f870a785318e6787")
			.unwrap()
			.try_into()
			.unwrap();
		let acc = AccountId20::from(hex_acc);

		let pk = ecdsa::Pair::from_seed_slice(&sk).unwrap().public();
		let signer: EthereumSigner = pk.into();

		assert_eq!(signer.into_account(), acc);
	}

	#[test]
	fn test_from_h160() {
		let m = hex::decode("28490327ff4e60d44b8aadf5478266422ed01232cc712c2d617e5c650ca15b85")
			.unwrap();
		let old: AccountId20 = H160::from(H256::from(keccak_256(&m))).into();
		let new: AccountId20 = H160::from_slice(&keccak_256(&m)[12..32]).into();
		assert_eq!(new, old);
	}

	#[test]
	fn test_account_display() {
		let pk = ecdsa::Pair::from_string("//Alice", None)
			.expect("static values are valid; qed")
			.public();
		let signer: EthereumSigner = pk.into();
		let account: AccountId20 = signer.into_account();
		let account_fmt = format!("{account}");
		assert_eq!(account_fmt, "0xE04CC55ebEE1cBCE552f250e85c57B70B2E2625b");
	}

	// PQC-only guarantee: a cryptographically VALID secp256k1 signature — one that
	// would authenticate under classical Ethereum ECDSA recovery — must be rejected
	// by `EthereumSignature::verify`, so no signed Substrate extrinsic can ever be
	// authenticated with classical crypto. If someone re-enables ECDSA verification,
	// this test fails.
	#[test]
	fn valid_secp256k1_signature_is_rejected_on_pqc_chain() {
		use sp_core::Pair as _;
		use sp_runtime::traits::Verify;

		// Deterministic secp256k1 key and its Ethereum-style AccountId20.
		let pair = ecdsa::Pair::from_seed_slice(&[7u8; 32]).unwrap();
		let signer: EthereumSigner = pair.public().into();
		let account: AccountId20 = signer.into_account();

		// Sign keccak_256(msg) — the exact hash the (former) verify path recovered
		// against — so this signature genuinely authenticates `account` under
		// classical Ethereum ECDSA.
		let msg = b"pqc-only: classical signatures must not authenticate";
		let m = keccak_256(msg);
		let eth_sig = EthereumSignature::new(pair.sign_prehashed(&m));

		assert!(
			!eth_sig.verify(&msg[..], &account),
			"a valid classical ECDSA signature must be rejected on a PQC-only chain",
		);
	}

	// ── PQC signed-extrinsic path ──────────────────────────────────────────
	use blackchain_crypto_lib_rust::{sign_message, BlackChainPrivateKey};
	use sp_runtime::traits::Verify;

	fn pqc_key(seed_byte: u8) -> BlackChainPrivateKey {
		let (k, _) = BlackChainPrivateKey::generate(&[seed_byte; 64]).expect("keygen");
		k
	}

	fn pqc_address(k: &BlackChainPrivateKey) -> AccountId20 {
		let pk = k.public_key().to_bytes();
		AccountId20(
			keccak_256(&pk)[12..]
				.try_into()
				.expect("20-byte slice; qed"),
		)
	}

	/// The runtime's address rule (`keccak256(pub_key)[12..]` via `PqcSigner`)
	/// matches the crypto library's own `derive_address`.
	#[test]
	fn pqc_signer_matches_library_address_derivation() {
		let k = pqc_key(1);
		let lib_addr = k.public_key().derive_address();
		let signer = PqcSigner(
			keccak_256(&k.public_key().to_bytes())[12..]
				.try_into()
				.unwrap(),
		);
		assert_eq!(signer.into_account().0, lib_addr.into_array());
	}

	/// A correctly domain-tagged, PQC-signed payload authenticates the signer; a
	/// wrong signer, tampered signature, or missing domain tag all fail.
	#[test]
	fn pqc_signature_verifies_signed_extrinsic_payload() {
		let k = pqc_key(2);
		let account = pqc_address(&k);
		let payload = b"(call, extra, additional_signed) encoded".to_vec();

		// Sign exactly what `PqcSignature::verify` reconstructs: TAG ‖ payload.
		let mut signed = EXTRINSIC_DOMAIN_TAG.to_vec();
		signed.extend_from_slice(&payload);
		let signature = sign_message(&signed, &k).expect("sign");
		let pub_key = k.public_key().to_bytes();

		let sig = PqcSignature::new(pub_key, signature);

		assert!(sig.verify(&payload[..], &account), "valid signature authenticates signer");

		// Wrong signer.
		let other = pqc_address(&pqc_key(3));
		assert!(!sig.verify(&payload[..], &other), "wrong signer rejected");

		// Tampered signature.
		let mut bad = sig.clone();
		bad.signature[0] ^= 0xFF;
		assert!(!bad.verify(&payload[..], &account), "tampered signature rejected");

		// Signature made WITHOUT the domain tag must not authenticate (cross-path).
		let plain = sign_message(&payload, &k).expect("sign");
		let no_tag = PqcSignature::new(k.public_key().to_bytes(), plain);
		assert!(!no_tag.verify(&payload[..], &account), "missing domain tag rejected");
	}

	/// Wrong-length public key / signature are rejected by the cheap pre-check.
	#[test]
	fn pqc_signature_rejects_malformed_lengths() {
		let k = pqc_key(4);
		let account = pqc_address(&k);
		let short = PqcSignature::new(vec![0u8; 10], vec![0u8; 10]);
		assert!(!short.verify(&b"x"[..], &account));
	}
}
