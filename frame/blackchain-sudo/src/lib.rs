// pallet-blackchain-sudo
//
// A PQC-authenticated admin/sudo pallet. On a BlackChain-only chain every classic
// signed Substrate extrinsic is disabled (`EthereumSignature::verify -> false`), so
// `pallet-sudo`, governance and `System::set_code` are all unreachable — the chain
// is unupgradeable. This pallet restores a privileged path WITHOUT reintroducing
// classical signatures: a single self-contained `sudo` extrinsic dispatches an
// arbitrary call with `Root` origin, authorised by a composite hybrid signature
// (Dilithium5 + P-521 + Ed448) from the configured admin key.
//
// ## How it works
//
// * The admin PQC-signs a domain-separated payload
//     `DOMAIN_TAG ‖ chain_id ‖ admin_nonce ‖ SCALE(call)`
//   with the generic `sign_message` scheme, producing the usual 4873-byte
//   composite signature and 2782-byte composite public key.
// * `sudo { call, nonce, pub_key, signature }` is a **self-contained** call
//   (like `pallet_ethereum::transact_blackchain`). `check_self_contained`
//   verifies the signature (native full crypto; WASM via the
//   `verify_pqc_message` host function) and recovers the signer address
//   `keccak256(pub_key)[12..]`.
// * `validate`/`pre_dispatch` pin the signer to the on-chain `AdminKey` and
//   enforce `nonce == AdminNonce` (replay protection at the STF level).
// * Dispatch consumes the nonce and runs the inner call with `Root`.
//
// The chain id and admin nonce live INSIDE the signed payload, so a signature is
// bound to this chain and cannot be replayed (cross-chain or same-chain).

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_crate_dependencies)]

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

// The host-function bridge is only referenced from the no_std (WASM) verification
// path; mark it used under std so `unused_crate_dependencies` stays quiet there.
#[cfg(feature = "std")]
use pallet_ethereum_blackchain_hf as _;

use frame_support::{
	dispatch::{
		DispatchInfo, DispatchResultWithPostInfo, GetDispatchInfo, Pays, PostDispatchInfo,
	},
	pallet_prelude::*,
	traits::UnfilteredDispatchable,
	weights::Weight,
};
use frame_system::pallet_prelude::*;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H160;
use sp_runtime::{
	traits::{Dispatchable, DispatchInfoOf},
	transaction_validity::{
		InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransactionBuilder,
	},
	RuntimeDebug,
};

/// Composite public key size: ML-DSA-87-pk(2592) + P521-pk(133) + Ed448-pk(57).
pub const COMPOSITE_PK_SIZE: usize = 2782;
/// Composite signature size: ML-DSA-87-sig(4627) + P521-sig(132) + Ed448-sig(114).
pub const COMPOSITE_SIG_SIZE: usize = 4873;

/// Domain-separation tag mixed into the signed payload. Bumping the version here
/// invalidates all previously-produced admin signatures.
pub const SUDO_DOMAIN_TAG: &[u8] = b"BLACKCHAIN_SUDO_V1";

/// Custom origin carrying the recovered, verified admin address.
///
/// This origin can ONLY be produced by the self-contained apply path after
/// `check_self_contained` has verified the composite signature — it is never
/// forgeable from extrinsic data, exactly like `pallet_ethereum::RawOrigin`.
#[derive(Clone, Eq, PartialEq, RuntimeDebug)]
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub enum RawOrigin {
	BlackchainAdmin(H160),
}

/// Ensure an outer origin is a verified BlackChain admin origin, returning the
/// admin address.
pub fn ensure_blackchain_admin<OuterOrigin>(o: OuterOrigin) -> Result<H160, &'static str>
where
	OuterOrigin: Into<Result<RawOrigin, OuterOrigin>>,
{
	match o.into() {
		Ok(RawOrigin::BlackchainAdmin(a)) => Ok(a),
		_ => Err("bad origin: expected a BlackChain admin origin"),
	}
}

pub use pallet::*;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::origin]
	pub type Origin = RawOrigin;

	#[pallet::config]
	// `RuntimeEvent` is bound on the supertrait instead of declared as an associated type
	// (declaring it is deprecated since polkadot-sdk #7229 — the bound is appended automatically).
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// A sudo-able call: the privileged call dispatched with `Root`.
		type RuntimeCall: Parameter
			+ UnfilteredDispatchable<RuntimeOrigin = Self::RuntimeOrigin>
			+ GetDispatchInfo;

		/// Chain id folded into the signed payload for cross-chain replay protection.
		#[pallet::constant]
		type ChainId: Get<u64>;
	}

	/// The composite-PQC admin address (`keccak256(pub_key)[12..]`) authorised to
	/// dispatch `Root` calls. `None` disables the admin path entirely.
	#[pallet::storage]
	pub type AdminKey<T: Config> = StorageValue<_, H160, OptionQuery>;

	/// Monotonic admin nonce. Every accepted `sudo` must carry `nonce == AdminNonce`
	/// and bumps it by one — replay protection for privileged calls.
	#[pallet::storage]
	pub type AdminNonce<T: Config> = StorageValue<_, u64, ValueQuery>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		/// Initial admin PQC address. `None` leaves the admin path disabled.
		pub admin_key: Option<H160>,
		#[serde(skip)]
		pub _marker: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			if let Some(key) = self.admin_key {
				AdminKey::<T>::put(key);
			}
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A privileged call was dispatched by the admin. `success` reflects the
		/// inner call's result (the sudo wrapper itself still succeeds).
		Sudid { admin: H160, nonce: u64, success: bool },
		/// The admin key was rotated.
		AdminKeyChanged { old: Option<H160>, new: H160 },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Signature valid but the signer is not the configured admin key.
		RequireAdmin,
		/// The admin nonce did not match the expected value.
		BadNonce,
		/// The composite signature failed verification.
		InvalidSignature,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		OriginFor<T>: Into<Result<RawOrigin, OriginFor<T>>>,
	{
		/// Dispatch a call with `Root` origin, authorised by the admin's composite
		/// PQC signature. This is a self-contained extrinsic; the signature is
		/// verified in `check_self_contained` before this runs.
		#[pallet::call_index(0)]
		#[pallet::weight({
			let di = call.get_dispatch_info();
			(
				di.call_weight.saturating_add(Weight::from_parts(25_000_000, 0)),
				di.class,
			)
		})]
		pub fn sudo(
			origin: OriginFor<T>,
			call: Box<<T as Config>::RuntimeCall>,
			nonce: u64,
			pub_key: Vec<u8>,
			signature: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			// `pub_key`/`signature` were already verified in `check_self_contained`;
			// the verified admin address is carried by the origin.
			let _ = (&pub_key, &signature);

			let admin = ensure_blackchain_admin(origin).map_err(|_| Error::<T>::RequireAdmin)?;
			ensure!(
				AdminKey::<T>::get() == Some(admin),
				Error::<T>::RequireAdmin
			);
			// STF-level replay protection: the nonce must be exactly the current one.
			ensure!(nonce == AdminNonce::<T>::get(), Error::<T>::BadNonce);
			AdminNonce::<T>::put(nonce.saturating_add(1));

			let res = call.dispatch_bypass_filter(frame_system::RawOrigin::Root.into());
			Self::deposit_event(Event::Sudid {
				admin,
				nonce,
				success: res.is_ok(),
			});

			// The admin does not pay a fee (there is no fee mechanism for this path).
			Ok(Pays::No.into())
		}

		/// Rotate the admin key. Requires `Root`, so it is itself invoked via `sudo`
		/// (the admin PQC-signs `sudo(set_key { new })`), giving PQC-authenticated
		/// key rotation.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(15_000_000, 0))]
		pub fn set_key(origin: OriginFor<T>, new: H160) -> DispatchResult {
			ensure_root(origin)?;
			let old = AdminKey::<T>::get();
			AdminKey::<T>::put(new);
			Self::deposit_event(Event::AdminKeyChanged { old, new });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Reconstruct the exact bytes the admin signed for a given inner call and
		/// nonce: `DOMAIN_TAG ‖ chain_id(LE) ‖ nonce(LE) ‖ SCALE(call)`.
		pub fn sudo_signing_payload(call: &<T as Config>::RuntimeCall, nonce: u64) -> Vec<u8> {
			let call_bytes = call.encode();
			let mut msg = Vec::with_capacity(
				SUDO_DOMAIN_TAG.len() + 8 + 8 + call_bytes.len(),
			);
			msg.extend_from_slice(SUDO_DOMAIN_TAG);
			msg.extend_from_slice(&T::ChainId::get().to_le_bytes());
			msg.extend_from_slice(&nonce.to_le_bytes());
			msg.extend_from_slice(&call_bytes);
			msg
		}

		/// Verify a composite PQC signature over `msg` and recover the signer.
		///
		/// Native (std): full Dilithium5+P-521+Ed448 verification. WASM (no_std):
		/// the `verify_pqc_message` host function (which runs the same native crypto
		/// on the host). Both return `keccak256(pub_key)[12..]` on success.
		pub fn recover_admin(msg: &[u8], signature: &[u8], pub_key: &[u8]) -> Option<H160> {
			#[cfg(feature = "std")]
			{
				match fp_blackchain_crypto::verify_message(msg, signature, pub_key) {
					Ok(addr) => Some(H160::from(addr)),
					Err(e) => {
						log::warn!(
							target: "blackchain_sudo",
							"admin signature verification failed: {e:?}"
						);
						None
					}
				}
			}
			#[cfg(not(feature = "std"))]
			{
				use pallet_ethereum_blackchain_hf::blackchain_crypto;
				let out =
					blackchain_crypto::verify_pqc_message(msg.to_vec(), signature.to_vec(), pub_key.to_vec());
				if out.len() == 20 {
					Some(H160::from_slice(&out))
				} else {
					None
				}
			}
		}
	}
}

// ── Self-contained call plumbing ────────────────────────────────────────────
// Mirrors `pallet_ethereum::Call`: the runtime's `SelfContainedCall` impl
// delegates to these inherent methods and, on success, dispatches the call with
// `RawOrigin::BlackchainAdmin(info)`.
impl<T: Config> Call<T>
where
	OriginFor<T>: Into<Result<RawOrigin, OriginFor<T>>>,
	T: Send + Sync,
	<T as frame_system::Config>::RuntimeCall:
		Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
	pub fn is_self_contained(&self) -> bool {
		matches!(self, Call::sudo { .. })
	}

	pub fn check_self_contained(&self) -> Option<Result<H160, TransactionValidityError>> {
		if let Call::sudo {
			call,
			nonce,
			pub_key,
			signature,
		} = self
		{
			// Cheap structural + authority pre-filter BEFORE the expensive verify.
			if pub_key.len() != COMPOSITE_PK_SIZE || signature.len() != COMPOSITE_SIG_SIZE {
				return Some(Err(InvalidTransaction::Custom(0).into()));
			}
			// The claimed admin is keccak256(pub_key)[12..], derivable without the
			// ~1.6 ms verify. If it is not the configured admin key, reject cheaply.
			let claimed =
				H160::from_slice(&sp_io::hashing::keccak_256(pub_key)[12..]);
			match AdminKey::<T>::get() {
				Some(k) if k == claimed => {}
				_ => return Some(Err(InvalidTransaction::BadSigner.into())),
			}

			// Expensive: verify the composite signature over the domain-separated
			// payload and confirm the recovered signer matches the claimed admin.
			let msg = Pallet::<T>::sudo_signing_payload(call, *nonce);
			match Pallet::<T>::recover_admin(&msg, signature, pub_key) {
				Some(addr) if addr == claimed => Some(Ok(addr)),
				_ => Some(Err(InvalidTransaction::Custom(0).into())),
			}
		} else {
			None
		}
	}

	pub fn validate_self_contained(
		&self,
		origin: &H160,
		_dispatch_info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
		_len: usize,
	) -> Option<TransactionValidity> {
		if let Call::sudo { nonce, .. } = self {
			match AdminKey::<T>::get() {
				Some(k) if k == *origin => {}
				_ => return Some(Err(InvalidTransaction::BadSigner.into())),
			}
			let current = AdminNonce::<T>::get();
			if *nonce < current {
				return Some(Err(InvalidTransaction::Stale.into()));
			}
			let mut builder = ValidTransactionBuilder::default().and_provides((*origin, *nonce));
			// `*nonce > current >= 0` here, so `*nonce >= 1`.
			if *nonce > current {
				builder = builder.and_requires((*origin, *nonce - 1));
			}
			Some(builder.build())
		} else {
			None
		}
	}

	pub fn pre_dispatch_self_contained(
		&self,
		origin: &H160,
		_dispatch_info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
		_len: usize,
	) -> Option<Result<(), TransactionValidityError>> {
		if let Call::sudo { nonce, .. } = self {
			match AdminKey::<T>::get() {
				Some(k) if k == *origin => {}
				_ => return Some(Err(InvalidTransaction::BadSigner.into())),
			}
			// STF replay protection: strict equality with the current admin nonce.
			let current = AdminNonce::<T>::get();
			if *nonce < current {
				return Some(Err(InvalidTransaction::Stale.into()));
			}
			if *nonce > current {
				return Some(Err(InvalidTransaction::Future.into()));
			}
			Some(Ok(()))
		} else {
			None
		}
	}
}
