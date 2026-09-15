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

//! # Ethereum pallet
//!
//! The Ethereum pallet works together with EVM pallet to provide full emulation
//! for Ethereum block processing.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(
	clippy::comparison_chain,
	clippy::large_enum_variant,
	clippy::useless_conversion
)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
// Production code must handle `Result`/`Option` explicitly (the denies above), but the mock
// runtime and unit tests legitimately use `unwrap`/`expect` and complex tuple types. Relax
// those lints for test builds only; this is inherited by every `#[cfg(test)]` module.
#![cfg_attr(
	test,
	allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)
)]
#![warn(unused_crate_dependencies)]

use pallet_ethereum_blackchain_hf as _;
// `frame-benchmarking` is an optional dependency only present under the
// `runtime-benchmarks` feature; gate the unused-dep suppressor accordingly so the
// plain (non-benchmark) WASM runtime build still compiles.
#[cfg(feature = "runtime-benchmarks")]
use frame_benchmarking as _;

extern crate alloc;

#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::BlackChainWeightInfo;

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use ethereum::eip2930::TransactionSignature as EIP1559Signature;
pub use ethereum::{
	AccessListItem, BlockV3 as Block, LegacyTransactionMessage, Log, ReceiptV4 as Receipt,
	TransactionAction, TransactionV3 as Transaction,
};
use ethereum_types::{Bloom, BloomInput, H160, H256, H64, U256};
use evm::ExitReason;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

// BlackChain PQC on-chain transaction type.
// Defined here (not imported) so WASM never links the crypto library.
// Only the std path in recover_blackchain_signer uses fp-blackchain-crypto.
#[derive(Clone, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
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
	pub input: alloc::vec::Vec<u8>,
	/// EIP-155 placeholder: chain_id * 2 + 35.
	pub v: u64,
	pub r: [u8; 32],
	pub s: [u8; 32],
	/// Composite PQC signature: [Dil5 ‖ P-521 ‖ Ed448].
	pub pqc_signature: alloc::vec::Vec<u8>,
	/// Composite public key: [Dil5 pk ‖ P-521 pk ‖ Ed448 pk] (2782 B).
	pub pub_key: alloc::vec::Vec<u8>,
}
// Substrate
use frame_support::{
	dispatch::{
		DispatchErrorWithPostInfo, DispatchInfo, DispatchResultWithPostInfo, Pays, PostDispatchInfo,
	},
	traits::{EnsureOrigin, Get, Time},
	weights::Weight,
};
use frame_system::{pallet_prelude::OriginFor, CheckWeight, WeightInfo};
use sp_runtime::{
	generic::DigestItem,
	traits::{DispatchInfoOf, Dispatchable, One, Saturating, UniqueSaturatedInto, Zero},
	transaction_validity::{
		InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransactionBuilder,
	},
	RuntimeDebug, SaturatedConversion,
};
use sp_version::RuntimeVersion;
// Frontier
use fp_consensus::{PostLog, PreLog, FRONTIER_ENGINE_ID};
pub use fp_ethereum::TransactionData;
use fp_ethereum::ValidatedTransaction as ValidatedTransactionT;
use fp_evm::{
	CallOrCreateInfo, CheckEvmTransaction, CheckEvmTransactionConfig, TransactionValidationError,
};
pub use fp_rpc::TransactionStatus;
use fp_storage::{EthereumStorageSchema, PALLET_ETHEREUM_SCHEMA};
use frame_support::traits::PalletInfoAccess;
use pallet_evm::{BlockHashMapping, FeeCalculator, GasWeightMapping, Runner};

#[derive(Clone, Eq, PartialEq, RuntimeDebug)]
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub enum RawOrigin {
	EthereumTransaction(H160),
}

pub fn ensure_ethereum_transaction<OuterOrigin>(o: OuterOrigin) -> Result<H160, &'static str>
where
	OuterOrigin: Into<Result<RawOrigin, OuterOrigin>>,
{
	match o.into() {
		Ok(RawOrigin::EthereumTransaction(n)) => Ok(n),
		_ => Err("bad origin: expected to be an Ethereum transaction"),
	}
}

pub struct EnsureEthereumTransaction;
impl<O: Into<Result<RawOrigin, O>> + From<RawOrigin>> EnsureOrigin<O>
	for EnsureEthereumTransaction
{
	type Success = H160;
	fn try_origin(o: O) -> Result<Self::Success, O> {
		o.into().map(|o| match o {
			RawOrigin::EthereumTransaction(id) => id,
		})
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin() -> Result<O, ()> {
		Ok(O::from(RawOrigin::EthereumTransaction(Default::default())))
	}
}

impl<T> Call<T>
where
	OriginFor<T>: Into<Result<RawOrigin, OriginFor<T>>>,
	T: Send + Sync + Config,
	T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
	pub fn is_self_contained(&self) -> bool {
		matches!(
			self,
			Call::transact { .. } | Call::transact_blackchain { .. }
		)
	}

	pub fn check_self_contained(&self) -> Option<Result<H160, TransactionValidityError>> {
		if let Call::transact { transaction } = self {
			let check = || {
				let origin = Pallet::<T>::recover_signer(transaction).ok_or(
					InvalidTransaction::Custom(TransactionValidationError::InvalidSignature as u8),
				)?;
				Ok(origin)
			};
			Some(check())
		} else if let Call::transact_blackchain { transaction } = self {
			// ── Fast O(1) structural pre-check gate (Mempool DoS Prevention) ─────
			// Perform cheap size validation BEFORE invoking expensive composite PQC
			// signature verification. Junk or malformed extrinsics drop in nanoseconds.
			// All three sub-signatures are fixed-width (ML-DSA-87 4627 ‖ P-521 132 ‖
			// Ed448 114), so a well-formed composite signature is EXACTLY 4873 bytes —
			// the crypto library rejects any other length (anti-malleability/padding).
			const COMPOSITE_PK_SIZE: usize = 2782;
			const COMPOSITE_SIG_SIZE: usize = 4873;

			if transaction.pub_key.len() != COMPOSITE_PK_SIZE
				|| transaction.pqc_signature.len() != COMPOSITE_SIG_SIZE
			{
				return Some(Err(InvalidTransaction::Custom(
					TransactionValidationError::InvalidSignature as u8,
				)
				.into()));
			}

			// ── Cheap economic pre-filter BEFORE the expensive PQC verify (CR-2) ─
			// The claimed sender is keccak256(pub_key)[12..], derivable WITHOUT
			// verifying the ~1.6 ms composite signature. Reject unpayable / wrong-
			// chain / underpriced spam here in microseconds so a zero-balance
			// attacker cannot force every node to run Dilithium5+P-521+Ed448 for a
			// transaction that could never pay. If the signature later proves
			// invalid we reject anyway; if valid, the recovered sender equals this
			// claimed address (asserted below), so vetting it now is sound.
			let claimed_origin =
				H160::from_slice(&sp_io::hashing::keccak_256(&transaction.pub_key)[12..]);
			match Pallet::<T>::blackchain_to_evm_transaction(transaction) {
				Some(evm_tx) => {
					if let Err(e) =
						Pallet::<T>::blackchain_precheck_economics(claimed_origin, &evm_tx)
					{
						return Some(Err(e));
					}
				}
				None => {
					return Some(Err(InvalidTransaction::Custom(
						TransactionValidationError::InvalidSignature as u8,
					)
					.into()))
				}
			}

			// Expensive path: full composite verification + sender recovery.
			let check = || {
				let origin = Pallet::<T>::recover_blackchain_signer(transaction).ok_or(
					InvalidTransaction::Custom(TransactionValidationError::InvalidSignature as u8),
				)?;
				// The economically-vetted claimed address MUST equal the verified
				// sender — otherwise the pre-filter checked a different account.
				if origin != claimed_origin {
					return Err(InvalidTransaction::Custom(
						TransactionValidationError::InvalidSignature as u8,
					)
					.into());
				}
				Ok(origin)
			};
			Some(check())
		} else {
			None
		}
	}

	pub fn pre_dispatch_self_contained(
		&self,
		origin: &H160,
		dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
		len: usize,
	) -> Option<Result<(), TransactionValidityError>> {
		if let Call::transact { transaction } = self {
			if let Err(e) =
				CheckWeight::<T>::do_validate(dispatch_info, len).and_then(|(_, next_len)| {
					CheckWeight::<T>::do_prepare(dispatch_info, len, next_len)
				}) {
				return Some(Err(e));
			}
			Some(Pallet::<T>::validate_transaction_in_block(
				*origin,
				transaction,
			))
	} else if let Call::transact_blackchain { transaction } = self {
			// ── WASM-safe binding check ─────────────────────────────────────────
			// Full Dilithium5+P521+Ed448 verification runs ONLY in native (std)
			// via check_self_contained.  In WASM we cannot re-run the same math,
			// but we CAN perform structural checks that prevent a malicious block
			// producer from injecting a forged extrinsic that bypasses the pool:
			//
			//  1. pub_key must be exactly COMPOSITE_PK_SIZE bytes — any other
			//     length is immediately invalid.
			//  2. pqc_signature must be at least the minimum composite length.
			//  3. keccak256(pub_key)[12..] must equal *origin* — this pins the
			//     public key to the sender address that native check already
			//     validated.  An attacker who swaps in a different pub_key would
			//     produce a different address and this check would reject it.
			// Hardcoded protocol constants — valid in both std and WASM (no_std).
		// COMPOSITE_PK_SIZE  = 2782: ML-DSA-87-pk(2592) + P521-pk(133) + Ed448-pk(57)
		// COMPOSITE_SIG_SIZE = 4873: ML-DSA-87-sig(4627) + P521-sig(132, fixed r‖s) + Ed448-sig(114)
		const COMPOSITE_PK_SIZE: usize = 2782;
		const COMPOSITE_SIG_SIZE: usize = 4873;

			// Check 1: public key structural size
			if transaction.pub_key.len() != COMPOSITE_PK_SIZE {
				return Some(Err(InvalidTransaction::Custom(
					TransactionValidationError::InvalidSignature as u8,
				)
				.into()));
			}

			// Check 2: signature must be exactly the fixed composite size
			if transaction.pqc_signature.len() != COMPOSITE_SIG_SIZE {
				return Some(Err(InvalidTransaction::Custom(
					TransactionValidationError::InvalidSignature as u8,
				)
				.into()));
			}

			// Check 3: pub_key must hash to the claimed origin address
			let derived_hash = sp_io::hashing::keccak_256(&transaction.pub_key);
			let derived_addr = H160::from_slice(&derived_hash[12..]);
			if derived_addr != *origin {
				return Some(Err(InvalidTransaction::Custom(
					TransactionValidationError::InvalidSignature as u8,
				)
				.into()));
			}

			// Weight check
			if let Err(e) =
				CheckWeight::<T>::do_validate(dispatch_info, len).and_then(|(_, next_len)| {
					CheckWeight::<T>::do_prepare(dispatch_info, len, next_len)
				}) {
				return Some(Err(e));
			}

			// ── STF validation (replay / double-spend protection) ───────────────
			// This is the CONSENSUS-CRITICAL check the classic `transact` branch
			// performs above via `validate_transaction_in_block`. Without it the
			// blackchain path applies with `validate = false` and the EVM runner
			// never checks nonce / balance / base-fee / chain_id — so any validly
			// signed transfer could be replayed (a stale nonce would execute again).
			//
			// We reconstruct the byte-identical EVM transaction that dispatch will
			// execute and run the same full validation. `validate_transaction_in_block`
			// requires `tx.nonce == account.nonce` exactly, rejecting both stale
			// (already-spent) and future nonces, and also enforces chain_id, base-fee
			// and balance. This runs in native (pool import) AND WASM (block execution),
			// so a malicious block author cannot smuggle a stale-nonce tx past it.
			let evm_tx = match Pallet::<T>::blackchain_to_evm_transaction(transaction) {
				Some(tx) => tx,
				None => {
					return Some(Err(InvalidTransaction::Custom(
						TransactionValidationError::InvalidSignature as u8,
					)
					.into()))
				}
			};
			Some(Pallet::<T>::validate_transaction_in_block(*origin, &evm_tx))
		} else {
			None
		}
	}

	pub fn validate_self_contained(
		&self,
		origin: &H160,
		dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
		len: usize,
	) -> Option<TransactionValidity> {
		if let Call::transact { transaction } = self {
			if let Err(e) = CheckWeight::<T>::do_validate(dispatch_info, len) {
				return Some(Err(e));
			}
			Some(Pallet::<T>::validate_transaction_in_pool(
				*origin,
				transaction,
			))
		} else if let Call::transact_blackchain { transaction } = self {
			if let Err(e) = CheckWeight::<T>::do_validate(dispatch_info, len) {
				return Some(Err(e));
			}

			// Signature was already checked in check_self_contained. Now run the full
			// pool-level validation on the byte-identical EVM transaction: stale-nonce
			// rejection, base-fee, balance, chain_id and gas-limit checks, plus the
			// provides/requires nonce tags used for mempool ordering. This mirrors the
			// classic `transact` branch and drops replayed / unpayable / junk txs at
			// admission instead of letting them sit in the mempool.
			let evm_tx = match Pallet::<T>::blackchain_to_evm_transaction(transaction) {
				Some(tx) => tx,
				None => {
					return Some(Err(InvalidTransaction::Custom(
						TransactionValidationError::InvalidSignature as u8,
					)
					.into()))
				}
			};
			Some(Pallet::<T>::validate_transaction_in_pool(*origin, &evm_tx))
		} else {
			None
		}
	}
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub enum PostLogContent {
	#[default]
	BlockAndTxnHashes,
	OnlyBlockHash,
}

pub use self::pallet::*;

#[frame_support::pallet]
#[allow(clippy::expect_used)]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::origin]
	pub type Origin = RawOrigin;

	#[pallet::config(with_default)]
	pub trait Config: frame_system::Config + pallet_evm::Config {
		/// How Ethereum state root is calculated.
		type StateRoot: Get<H256>;
		/// What's included in the PostLog.
		type PostLogContent: Get<PostLogContent>;
		/// The maximum length of the extra data in the Executed event.
		type ExtraDataLength: Get<u32>;
		/// Weight information for BlackChain PQC extrinsics.
		///
		/// Implement this using the output of:
		///   `benchmark pallet --extrinsic=pqc_verify_signature ...`
		/// Until then, the default `()` implementation uses a conservative placeholder.
		type BlackChainWeightInfo: BlackChainWeightInfo;
	}

	pub mod config_preludes {
		use super::*;
		use frame_support::{derive_impl, parameter_types};

		pub struct TestDefaultConfig;

		#[derive_impl(frame_system::config_preludes::TestDefaultConfig, no_aggregated_types)]
		impl frame_system::DefaultConfig for TestDefaultConfig {}

		#[derive_impl(pallet_evm::config_preludes::TestDefaultConfig, no_aggregated_types)]
		impl pallet_evm::DefaultConfig for TestDefaultConfig {}

		parameter_types! {
			pub const PostBlockAndTxnHashes: PostLogContent = PostLogContent::BlockAndTxnHashes;
		}

		#[register_default_impl(TestDefaultConfig)]
		impl DefaultConfig for TestDefaultConfig {
			type StateRoot = IntermediateStateRoot<Self::Version>;
			type PostLogContent = PostBlockAndTxnHashes;
			type ExtraDataLength = ConstU32<30>;
			// Use the () fallback weight for tests — no benchmarking needed.
			type BlackChainWeightInfo = ();
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_finalize(n: BlockNumberFor<T>) {
			<Pallet<T>>::store_block(
				match fp_consensus::find_pre_log(&frame_system::Pallet::<T>::digest()) {
					Ok(_) => None,
					Err(_) => Some(T::PostLogContent::get()),
				},
				U256::from(UniqueSaturatedInto::<u128>::unique_saturated_into(
					frame_system::Pallet::<T>::block_number(),
				)),
			);
			// move block hash pruning window by one block
			let block_hash_count = T::BlockHashCount::get();
			let to_remove = n
				.saturating_sub(block_hash_count)
				.saturating_sub(One::one());
			// keep genesis hash
			if !to_remove.is_zero() {
				<BlockHash<T>>::remove(U256::from(
					UniqueSaturatedInto::<u32>::unique_saturated_into(to_remove),
				));
			}
		}

		fn on_initialize(_: BlockNumberFor<T>) -> Weight {
			let mut weight = T::SystemWeightInfo::kill_storage(1);

			// If the digest contain an existing ethereum block(encoded as PreLog), If contains,
			// execute the imported block firstly and disable transact dispatch function.
			if let Ok(log) = fp_consensus::find_pre_log(&frame_system::Pallet::<T>::digest()) {
				let PreLog::Block(block) = log;

				for transaction in block.transactions {
					// CONSENSUS SAFETY: Pre-log block import executes transactions from a pre-sealed
					// block digest. If signature recovery or transaction validation fails here,
					// continuing would cause silent state-root divergence across nodes.
					// Halting execution via expect() is the required Substrate fail-safe.
					#[allow(clippy::expect_used)]
					let source = Self::recover_signer(&transaction).expect(
						"pre-block transaction signature invalid; the block cannot be built",
					);

					#[allow(clippy::expect_used)]
					Self::validate_transaction_in_block(source, &transaction).expect(
						"pre-block transaction verification failed; the block cannot be built",
					);

					#[allow(clippy::expect_used)]
					let (r, _) = Self::apply_validated_transaction(source, transaction, None)
						.expect("pre-block apply transaction failed; the block cannot be built");

					weight = weight.saturating_add(r.actual_weight.unwrap_or_default());
				}
			}
			// Account for `on_finalize` weight:
			//	- read: frame_system::Pallet::<T>::digest()
			//	- read: frame_system::Pallet::<T>::block_number()
			//	- write: <Pallet<T>>::store_block()
			//	- write: <BlockHash<T>>::remove()
			weight.saturating_add(T::DbWeight::get().reads_writes(2, 2))
		}

		fn on_runtime_upgrade() -> Weight {
			frame_support::storage::unhashed::put::<EthereumStorageSchema>(
				PALLET_ETHEREUM_SCHEMA,
				&EthereumStorageSchema::V3,
			);

			T::DbWeight::get().writes(1)
		}
	}

	/// Conservative upper-bound on the ref_time cost of verifying one composite PQC signature
	/// (Dilithium5 + NIST P-521 + Ed448).
	///
	/// **This value is a placeholder and MUST be replaced with actual `frame-benchmarking`
	/// measurements on target validator hardware before any production deployment.**
	///
	/// Rough estimates from dev hardware (Apple M-series):
	///   Dilithium5 verify ≈ 0.5 ms, P-521 verify ≈ 1.5 ms, Ed448 verify ≈ 2.5 ms
	///   Total ≈ ~5 ms → 500_000 Weight ref_time units (at 1 picosecond per unit)
	///
	/// Set 10× conservatively (5_000_000) to leave a margin against slower hardware
	/// and WASM overhead until real benchmarks are available.
	pub const PQC_VERIFY_OVERHEAD_REF_TIME: u64 = 5_000_000;

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		OriginFor<T>: Into<Result<RawOrigin, OriginFor<T>>>,
	{
		/// Transact an Ethereum transaction.
		#[pallet::call_index(0)]
		#[pallet::weight({
			let without_base_extrinsic_weight = true;
			<T as pallet_evm::Config>::GasWeightMapping::gas_to_weight({
				let transaction_data: TransactionData = transaction.into();
				transaction_data.gas_limit.unique_saturated_into()
			}, without_base_extrinsic_weight)
		})]
		pub fn transact(
			origin: OriginFor<T>,
			transaction: Transaction,
		) -> DispatchResultWithPostInfo {
			let source = ensure_ethereum_transaction(origin)?;
			// Disable transact functionality if PreLog exist.
			assert!(
				fp_consensus::find_pre_log(&frame_system::Pallet::<T>::digest()).is_err(),
				"pre log already exists; block is invalid",
			);

			Self::apply_validated_transaction(source, transaction, None)
				.map(|(post_info, _)| post_info)
		}

		/// Transact a BlackChain hybrid PQC transaction (Option B wire format).
		///
		/// This extrinsic is the production-grade entry point for submitting
		/// BlackChain transactions signed with the Dilithium5 + P-521 + Ed448
		/// composite scheme.
		///
		/// Classic secp256k1 ECDSA is NOT used.  The sender address is derived
		/// from the composite public key embedded in the transaction.
		#[pallet::call_index(1)]
		#[pallet::weight({
			let without_base_extrinsic_weight = true;
			let evm_weight = <T as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
				transaction.gas_limit,
				without_base_extrinsic_weight,
			);
			// Add the PQC signature-verification overhead on top of EVM gas cost.
			// This uses T::BlackChainWeightInfo::pqc_verify_signature() which is
			// populated from `frame-benchmarking` measurements. Run:
			//   benchmark pallet --extrinsic=pqc_verify_signature
			// and set type BlackChainWeightInfo = SubstrateWeight<Runtime> in your runtime.
			evm_weight.saturating_add(T::BlackChainWeightInfo::pqc_verify_signature())
		})]
		pub fn transact_blackchain(
			origin: OriginFor<T>,
			transaction: BlackChainTransaction,
		) -> DispatchResultWithPostInfo {
			// Prevent transact when PreLog already exists
			ensure!(
				fp_consensus::find_pre_log(&frame_system::Pallet::<T>::digest()).is_err(),
				Error::<T>::PreLogExists,
			);

			// The composite signature was ALREADY verified in `check_self_contained`
			// (which runs at pool admission AND during block import), and the verified
			// sender is carried by the self-contained origin. Re-running the full
			// Dilithium5 + P-521 + Ed448 verification here would DOUBLE the ~1.6 ms
			// verify cost per transaction during block import, while the declared
			// weight accounts for only one verify (audit HI-6). So we trust the origin
			// and confirm — with a cheap keccak, NOT a second signature verification —
			// that the transaction's public key hashes to it. This is exactly the pin
			// the WASM `pre_dispatch_self_contained` already enforces, so it can never
			// fail for a transaction that reached dispatch through the self-contained
			// path; it is defence-in-depth that costs microseconds, not milliseconds.
			let source = ensure_ethereum_transaction(origin)?;
			let derived =
				H160::from_slice(&sp_io::hashing::keccak_256(&transaction.pub_key)[12..]);
			ensure!(derived == source, Error::<T>::InvalidSignature);

			// Build an equivalent Ethereum EIP-1559 transaction for the EVM pipeline.
			// The EVM runner does not care about the signature format; it only needs
			// the execution parameters (to, value, gas, data). This MUST be identical
			// to the transaction validated in `pre_dispatch_self_contained`, so both
			// share `blackchain_to_evm_transaction`.
			//
			// Nonce / balance / base-fee / chain_id are enforced in
			// `pre_dispatch_self_contained` (the STF gate that runs before this
			// dispatch), mirroring the classic `transact` path. `transact_blackchain`
			// requires a `RawOrigin::EthereumTransaction` origin, which only the
			// self-contained machinery supplies, so it can never be dispatched
			// bypassing that gate.
			let evm_tx = Self::blackchain_to_evm_transaction(&transaction).ok_or(
				DispatchError::Other(
					"BlackChain: failed to construct derived EIP1559 placeholder signature",
				),
			)?;

			Self::apply_validated_transaction(source, evm_tx, None).map(|(post_info, _)| post_info)
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event {
		/// An ethereum transaction was successfully executed.
		Executed {
			from: H160,
			to: H160,
			transaction_hash: H256,
			exit_reason: ExitReason,
			extra_data: Vec<u8>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Signature is invalid.
		InvalidSignature,
		/// Pre-log is present, therefore transact is not allowed.
		PreLogExists,
	}

	/// Mapping from transaction index to transaction in the current building block.
	#[pallet::storage]
	pub type Pending<T: Config> =
		CountedStorageMap<_, Identity, u32, (Transaction, TransactionStatus, Receipt), OptionQuery>;

	/// The current Ethereum block.
	#[pallet::storage]
	pub type CurrentBlock<T: Config> = StorageValue<_, ethereum::BlockV3>;

	/// The current Ethereum receipts.
	#[pallet::storage]
	pub type CurrentReceipts<T: Config> = StorageValue<_, Vec<Receipt>>;

	/// The current transaction statuses.
	#[pallet::storage]
	pub type CurrentTransactionStatuses<T: Config> = StorageValue<_, Vec<TransactionStatus>>;

	// Mapping for block number and hashes.
	#[pallet::storage]
	pub type BlockHash<T: Config> = StorageMap<_, Twox64Concat, U256, H256, ValueQuery>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T> {
		#[serde(skip)]
		pub _marker: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			<Pallet<T>>::store_block(None, U256::zero());
			frame_support::storage::unhashed::put::<EthereumStorageSchema>(
				PALLET_ETHEREUM_SCHEMA,
				&EthereumStorageSchema::V3,
			);
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn transaction_weight(transaction_data: &TransactionData) -> (Option<Weight>, Option<u64>) {
		match <T as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
			transaction_data.gas_limit.unique_saturated_into(),
			true,
		) {
			weight_limit if weight_limit.proof_size() > 0 => (
				Some(weight_limit),
				Some(transaction_data.proof_size_base_cost()),
			),
			_ => (None, None),
		}
	}

	fn recover_signer(transaction: &Transaction) -> Option<H160> {
		// All classic Ethereum transaction variants use secp256k1 ECDSA.
		// In a BlackChain-only network these variants are NOT accepted — returning
		// None causes the transaction to be rejected as InvalidSignature.
		//
		// NOTE: to accept both classic and BlackChain transactions, change the
		// arms below to call sp_io::crypto::secp256k1_ecdsa_recover instead.
		match transaction {
			Transaction::Legacy(_)
			| Transaction::EIP2930(_)
			| Transaction::EIP1559(_)
			| Transaction::EIP7702(_) => {
				// Classic ECDSA transactions are rejected on a BlackChain-only node.
				None
			}
		}
	}

	/// Recovers the sender address from a BlackChain hybrid PQC transaction.
	///
	/// ## Execution contexts
	///
	/// - **Native / std** (`check_self_contained`, transaction pool): Runs the full
	///   composite signature verification via `verify_blackchain_tx()` from the library.
	///   All three sub-signatures (Dilithium5 + P-521 + Ed448) are checked.
	///
	/// - **WASM / no_std** (block execution): By the time WASM executes this, the
	///   native executor has *already* verified the signature in `check_self_contained`.
	///   We only derive the sender address from the composite public key bytes using
	///   `keccak_256`, which is available as a host function in WASM.
	pub fn recover_blackchain_signer(tx: &BlackChainTransaction) -> Option<H160> {
		#[cfg(feature = "std")]
		{
			use alloy_primitives::{
				Address as AlloyAddress, Bytes as AlloyBytes, U256 as AlloyU256,
			};
			use fp_blackchain_crypto::{verify_blackchain_tx, BlackChainTxType};

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
				data: AlloyBytes::from(tx.input.clone()),
				v: Some(AlloyU256::from(tx.v)),
				r: Some(AlloyU256::ZERO),
				s: Some(AlloyU256::ZERO),
				pqc_signature: Some(AlloyBytes::from(tx.pqc_signature.clone())),
				pub_key: Some(AlloyBytes::from(tx.pub_key.clone())),
			};

			log::debug!(
				target: "ethereum",
				"Verifying BlackChain PQC transaction: chain_id={}, nonce={}, gas_limit={}, pub_key_len={}, sig_len={}",
				tx.chain_id,
				tx.nonce,
				tx.gas_limit,
				tx.pub_key.len(),
				tx.pqc_signature.len()
			);

			match verify_blackchain_tx(&lib_tx) {
				Ok(alloy_addr) => {
					let address = H160::from_slice(alloy_addr.as_slice());
					log::info!(
						target: "ethereum",
						"Successfully verified BlackChain PQC signature. Recovered sender address: {address:?}"
					);
					Some(address)
				}
				Err(e) => {
					log::error!(
						target: "ethereum",
						"Failed to verify BlackChain PQC signature: {e:?}"
					);
					None
				}
			}
		}

		// WASM executor path:
		// Full Dilithium5+P-521+Ed448 verification runs on the HOST (native) side
		// via the `blackchain_crypto::verify_pqc_transaction` host function.
		//
		// The entire BlackChainTransaction is SCALE-encoded into a single Vec<u8>
		// (avoiding all RIType constraints), passed to the host, which decodes,
		// reconstructs BlackChainTxType, and runs fp_blackchain_crypto::verify_blackchain_tx.
		//
		// Returns 20 bytes (H160) on success, empty Vec on failure.
		#[cfg(not(feature = "std"))]
		{
			use pallet_ethereum_blackchain_hf::blackchain_crypto;
			use scale_codec::Encode;

			let encoded = tx.encode();
			let result = blackchain_crypto::verify_pqc_transaction(encoded);

			if result.len() == 20 {
				Some(H160::from_slice(&result))
			} else {
				None
			}
		}
	}

	/// Build the equivalent Ethereum EIP-1559 transaction for a BlackChain PQC
	/// transaction.
	///
	/// The EVM pipeline (execution, fee/nonce/balance validation) only needs the
	/// execution parameters (chain_id, nonce, fees, gas, to, value, data). The
	/// signature format is irrelevant to it, so we synthesise a deterministic
	/// placeholder `r`/`s` derived from the composite PQC signature — this gives
	/// every distinct PQC transaction a unique Ethereum-level hash (a constant
	/// r/s would collide for two PQC txs sharing the same fields).
	///
	/// ⚠ The resulting `r`/`s`/`v` are NON-CRYPTOGRAPHIC PLACEHOLDERS — they are not
	/// an ECDSA signature over anything. `ecrecover(r,s,v)` on the returned tx yields
	/// a meaningless address (audit HI-8). The authoritative sender is
	/// `keccak256(pub_key)[12..]`; explorers/indexers should read `from` from the tx
	/// status or the `blackchain_getTransactionByHash` RPC (which returns the real
	/// composite public key + signature), never recover it from `r`/`s`/`v`.
	///
	/// This single construction is shared by `pre_dispatch_self_contained`
	/// (STF nonce/fee/balance/chain_id validation), `validate_self_contained`
	/// (pool validation) and `transact_blackchain` (dispatch) so all three
	/// operate on byte-identical transactions — a divergence between validation
	/// and execution would reopen the replay window this closes.
	///
	/// Returns `None` only if the derived placeholder signature cannot be
	/// constructed (should never happen given the LSB-forcing below).
	pub fn blackchain_to_evm_transaction(tx: &BlackChainTransaction) -> Option<Transaction> {
		let action = if tx.is_create {
			TransactionAction::Create
		} else {
			TransactionAction::Call(H160::from_slice(&tx.to))
		};

		// Construction: sig_hash = keccak256(pqc_signature)
		//   r = sig_hash with the LSB forced to 1 (guarantees r != 0)
		//   s = keccak256(r_bytes) with the LSB forced to 1 (guarantees s != 0 and s != r)
		let sig_hash = sp_io::hashing::keccak_256(&tx.pqc_signature);
		let mut r_bytes = sig_hash;
		r_bytes[31] |= 0x01;
		let mut s_bytes = sp_io::hashing::keccak_256(&r_bytes);
		s_bytes[31] |= 0x01;
		let placeholder_sig = EIP1559Signature::new(
			false,
			ethereum_types::H256::from_slice(&r_bytes),
			ethereum_types::H256::from_slice(&s_bytes),
		)?;

		Some(Transaction::EIP1559(ethereum::EIP1559Transaction {
			chain_id: tx.chain_id,
			nonce: U256::from(tx.nonce),
			max_priority_fee_per_gas: U256::from_big_endian(&tx.max_priority_fee_per_gas),
			max_fee_per_gas: U256::from_big_endian(&tx.max_fee_per_gas),
			gas_limit: U256::from(tx.gas_limit),
			action,
			value: U256::from_big_endian(&tx.value),
			input: tx.input.clone(),
			access_list: vec![],
			signature: placeholder_sig,
		}))
	}

	/// Cheap economic pre-filter for a BlackChain transaction, run BEFORE the
	/// expensive composite PQC signature verification (mempool CPU-DoS defence,
	/// audit CR-2).
	///
	/// The claimed sender address of a BlackChain tx is `keccak256(pub_key)[12..]`
	/// and is derivable WITHOUT verifying the signature. That lets us reject spam
	/// (a zero-balance / wrong-chain / underpriced keypair) using only a couple of
	/// storage reads and a keccak — instead of forcing every node to burn ~1.6 ms
	/// on Dilithium5 + P-521 + Ed448 verification for a tx that can never pay.
	///
	/// This runs ONLY the three checks that are identical in the pool and in-block
	/// contexts and are a strict SUBSET of both `validate_transaction_in_pool` and
	/// `validate_transaction_in_block`: chain_id, base-fee and balance. It
	/// deliberately omits the nonce check (pool vs block differ; nonce ordering is
	/// enforced authoritatively later) so it can NEVER reject a transaction that the
	/// authoritative validation would accept — i.e. it introduces no consensus or
	/// mempool-behaviour divergence, only an early-out.
	fn blackchain_precheck_economics(
		origin: H160,
		transaction: &Transaction,
	) -> Result<(), TransactionValidityError> {
		let transaction_data: TransactionData = transaction.into();
		let (weight_limit, proof_size_base_cost) = Self::transaction_weight(&transaction_data);
		let (base_fee, _) = T::FeeCalculator::min_gas_price();
		let (who, _) = pallet_evm::Pallet::<T>::account_basic(&origin);

		let check = CheckEvmTransaction::<InvalidTransactionWrapper>::new(
			CheckEvmTransactionConfig {
				evm_config: T::config(),
				block_gas_limit: T::BlockGasLimit::get(),
				base_fee,
				chain_id: T::ChainId::get(),
				is_transactional: true,
			},
			transaction_data.into(),
			weight_limit,
			proof_size_base_cost,
		);
		check
			.with_chain_id()
			.and_then(|v| v.with_base_fee())
			.and_then(|v| v.with_balance_for(&who))
			.map_err(|e| TransactionValidityError::Invalid(e.0))?;

		Ok(())
	}

	fn store_block(post_log: Option<PostLogContent>, block_number: U256) {
		let transactions_count = Pending::<T>::count();
		let mut transactions = Vec::with_capacity(transactions_count as usize);
		let mut statuses = Vec::with_capacity(transactions_count as usize);
		let mut receipts = Vec::with_capacity(transactions_count as usize);
		let mut logs_bloom = Bloom::default();
		let mut cumulative_gas_used = U256::zero();
		for transaction_index in 0..transactions_count {
			if let Some((transaction, status, receipt)) = Pending::<T>::take(transaction_index) {
				transactions.push(transaction);
				statuses.push(status);
				receipts.push(receipt.clone());
				let (logs, used_gas) = match receipt {
					Receipt::Legacy(d) | Receipt::EIP2930(d) | Receipt::EIP1559(d) => {
						(d.logs.clone(), d.used_gas)
					}
					Receipt::EIP7702(d) => (d.logs.clone(), d.used_gas),
				};
				cumulative_gas_used = used_gas;
				Self::logs_bloom(logs, &mut logs_bloom);
			}
		}

		let ommers = Vec::<ethereum::Header>::new();
		let receipts_root = ethereum::util::ordered_trie_root(
			receipts.iter().map(ethereum::EnvelopedEncodable::encode),
		);
		let partial_header = ethereum::PartialHeader {
			parent_hash: if block_number > U256::zero() {
				BlockHash::<T>::get(block_number - 1)
			} else {
				H256::default()
			},
			beneficiary: pallet_evm::Pallet::<T>::find_author(),
			state_root: T::StateRoot::get(),
			receipts_root,
			logs_bloom,
			difficulty: U256::zero(),
			number: block_number,
			gas_limit: T::BlockGasLimit::get(),
			gas_used: cumulative_gas_used,
			timestamp: T::Timestamp::now().unique_saturated_into(),
			extra_data: Vec::new(),
			mix_hash: H256::default(),
			nonce: H64::default(),
		};
		let block = ethereum::Block::new(partial_header, transactions.clone(), ommers);

		CurrentBlock::<T>::put(block.clone());
		CurrentReceipts::<T>::put(receipts.clone());
		CurrentTransactionStatuses::<T>::put(statuses.clone());
		BlockHash::<T>::insert(block_number, block.header.hash());

		match post_log {
			Some(PostLogContent::BlockAndTxnHashes) => {
				let digest = DigestItem::Consensus(
					FRONTIER_ENGINE_ID,
					PostLog::Hashes(fp_consensus::Hashes::from_block(block)).encode(),
				);
				frame_system::Pallet::<T>::deposit_log(digest);
			}
			Some(PostLogContent::OnlyBlockHash) => {
				let digest = DigestItem::Consensus(
					FRONTIER_ENGINE_ID,
					PostLog::BlockHash(block.header.hash()).encode(),
				);
				frame_system::Pallet::<T>::deposit_log(digest);
			}
			None => { /* do nothing*/ }
		}
	}

	fn logs_bloom(logs: Vec<Log>, bloom: &mut Bloom) {
		for log in logs {
			bloom.accrue(BloomInput::Raw(&log.address[..]));
			for topic in log.topics {
				bloom.accrue(BloomInput::Raw(&topic[..]));
			}
		}
	}

	// Controls that must be performed by the pool.
	// The controls common with the State Transition Function (STF) are in
	// the function `validate_transaction_common`.
	fn validate_transaction_in_pool(
		origin: H160,
		transaction: &Transaction,
	) -> TransactionValidity {
		let transaction_data: TransactionData = transaction.into();
		let transaction_nonce = transaction_data.nonce;
		let (weight_limit, proof_size_base_cost) = Self::transaction_weight(&transaction_data);
		let (base_fee, _) = T::FeeCalculator::min_gas_price();
		let (who, _) = pallet_evm::Pallet::<T>::account_basic(&origin);

		// Check if this is an EIP-7702 transaction
		let is_eip7702 = matches!(transaction, Transaction::EIP7702(_));

		let _ = CheckEvmTransaction::<InvalidTransactionWrapper>::new(
			CheckEvmTransactionConfig {
				evm_config: T::config(),
				block_gas_limit: T::BlockGasLimit::get(),
				base_fee,
				chain_id: T::ChainId::get(),
				is_transactional: true,
			},
			transaction_data.clone().into(),
			weight_limit,
			proof_size_base_cost,
		)
		.validate_in_pool_for(&who)
		.and_then(|v| v.with_chain_id())
		.and_then(|v| v.with_base_fee())
		.and_then(|v| v.with_balance_for(&who))
		.and_then(|v| v.with_eip7702_authorization_list(is_eip7702))
		.map_err(|e| e.0)?;

		// EIP-3607: https://eips.ethereum.org/EIPS/eip-3607
		// Do not allow transactions for which `tx.sender` has any code deployed.
		// Exception: Allow transactions from EOAs whose code is a valid delegation indicator (0xef0100 || address).
		//
		// This check should be done on the transaction validation (here) **and**
		// on transaction execution, otherwise a contract tx will be included in
		// the mempool and pollute the mempool forever.
		if let Some(metadata) = pallet_evm::AccountCodesMetadata::<T>::get(origin) {
			if metadata.size > 0 {
				// Account has code, check if it's a valid delegation
				let is_delegation = metadata.size
					== evm::delegation::EIP_7702_DELEGATION_SIZE as u64
					&& pallet_evm::AccountCodes::<T>::get(origin)
						.starts_with(evm::delegation::EIP_7702_DELEGATION_PREFIX);

				if !is_delegation {
					return Err(InvalidTransaction::BadSigner.into());
				}
			}
		}

		let priority = match (
			transaction_data.gas_price,
			transaction_data.max_fee_per_gas,
			transaction_data.max_priority_fee_per_gas,
		) {
			// Legacy or EIP-2930 transaction.
			// Handle priority here. On legacy transaction everything in gas_price except
			// the current base_fee is considered a tip to the miner and thus the priority.
			(Some(gas_price), None, None) => {
				gas_price.saturating_sub(base_fee).unique_saturated_into()
			}
			// EIP-1559 transaction without tip.
			(None, Some(_), None) => 0,
			// EIP-1559 transaction with tip.
			(None, Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => max_fee_per_gas
				.saturating_sub(base_fee)
				.min(max_priority_fee_per_gas)
				.unique_saturated_into(),
			// Unreachable because already validated. Gracefully handle.
			_ => return Err(InvalidTransaction::Payment.into()),
		};

		// The tag provides and requires must be filled correctly according to the nonce.
		let mut builder = ValidTransactionBuilder::default()
			.and_provides((origin, transaction_nonce))
			.priority(priority);

		// In the context of the pool, a transaction with
		// too high a nonce is still considered valid
		if transaction_nonce > who.nonce {
			if let Some(prev_nonce) = transaction_nonce.checked_sub(1.into()) {
				builder = builder.and_requires((origin, prev_nonce))
			}
		}

		builder.build()
	}

	fn apply_validated_transaction(
		source: H160,
		transaction: Transaction,
		maybe_force_create_address: Option<H160>,
	) -> Result<(PostDispatchInfo, CallOrCreateInfo), DispatchErrorWithPostInfo> {
		let (to, _, info) = Self::execute(source, &transaction, None, maybe_force_create_address)?;

		let transaction_hash = transaction.hash();
		let transaction_index = Pending::<T>::count();

		let (reason, status, weight_info, used_gas, dest, extra_data) = match info.clone() {
			CallOrCreateInfo::Call(info) => (
				info.exit_reason.clone(),
				TransactionStatus {
					transaction_hash,
					transaction_index,
					from: source,
					to,
					contract_address: None,
					logs: info.logs.clone(),
					logs_bloom: {
						let mut bloom: Bloom = Bloom::default();
						Self::logs_bloom(info.logs, &mut bloom);
						bloom
					},
				},
				info.weight_info,
				info.used_gas,
				to,
				match info.exit_reason {
					ExitReason::Revert(_) => {
						const LEN_START: usize = 36;
						const MESSAGE_START: usize = 68;

						let data = info.value;
						let data_len = data.len();
						if data_len > MESSAGE_START {
							let message_len =
								U256::from_big_endian(&data[LEN_START..MESSAGE_START])
									.saturated_into::<usize>();
							let message_end = MESSAGE_START.saturating_add(
								message_len.min(T::ExtraDataLength::get() as usize),
							);

							if data_len >= message_end {
								data[MESSAGE_START..message_end].to_vec()
							} else {
								data
							}
						} else {
							data
						}
					}
					_ => vec![],
				},
			),
			CallOrCreateInfo::Create(info) => (
				info.exit_reason,
				TransactionStatus {
					transaction_hash,
					transaction_index,
					from: source,
					to,
					contract_address: Some(info.value),
					logs: info.logs.clone(),
					logs_bloom: {
						let mut bloom: Bloom = Bloom::default();
						Self::logs_bloom(info.logs, &mut bloom);
						bloom
					},
				},
				info.weight_info,
				info.used_gas,
				Some(info.value),
				Vec::new(),
			),
		};

		let receipt = {
			let status_code: u8 = match reason {
				ExitReason::Succeed(_) => 1,
				_ => 0,
			};
			let logs_bloom = status.logs_bloom;
			let logs = status.clone().logs;
			let cumulative_gas_used = if let Some((_, _, receipt)) =
				Pending::<T>::get(transaction_index.saturating_sub(1))
			{
				match receipt {
					Receipt::Legacy(d)
					| Receipt::EIP2930(d)
					| Receipt::EIP1559(d)
					| Receipt::EIP7702(d) => d.used_gas.saturating_add(used_gas.effective),
				}
			} else {
				used_gas.effective
			};
			match &transaction {
				Transaction::Legacy(_) => Receipt::Legacy(ethereum::EIP658ReceiptData {
					status_code,
					used_gas: cumulative_gas_used,
					logs_bloom,
					logs,
				}),
				Transaction::EIP2930(_) => Receipt::EIP2930(ethereum::EIP2930ReceiptData {
					status_code,
					used_gas: cumulative_gas_used,
					logs_bloom,
					logs,
				}),
				Transaction::EIP1559(_) => Receipt::EIP1559(ethereum::EIP2930ReceiptData {
					status_code,
					used_gas: cumulative_gas_used,
					logs_bloom,
					logs,
				}),
				Transaction::EIP7702(_) => Receipt::EIP7702(ethereum::EIP7702ReceiptData {
					status_code,
					used_gas: cumulative_gas_used,
					logs_bloom,
					logs,
				}),
			}
		};

		Pending::<T>::insert(transaction_index, (transaction, status, receipt));

		Self::deposit_event(Event::Executed {
			from: source,
			to: dest.unwrap_or_default(),
			transaction_hash,
			exit_reason: reason,
			extra_data,
		});

		Ok((
			PostDispatchInfo {
				actual_weight: {
					let mut gas_to_weight = T::GasWeightMapping::gas_to_weight(
						core::cmp::max(
							used_gas.standard.unique_saturated_into(),
							used_gas.effective.unique_saturated_into(),
						),
						true,
					);
					if let Some(weight_info) = weight_info {
						if let Some(proof_size_usage) = weight_info.proof_size_usage {
							*gas_to_weight.proof_size_mut() = proof_size_usage;
						}
					}
					Some(gas_to_weight)
				},
				pays_fee: Pays::No,
			},
			info,
		))
	}

	/// Get current block hash
	pub fn current_block_hash() -> Option<H256> {
		<CurrentBlock<T>>::get().map(|block| block.header.hash())
	}

	/// Execute an Ethereum transaction.
	pub fn execute(
		from: H160,
		transaction: &Transaction,
		config: Option<evm::Config>,
		maybe_force_create_address: Option<H160>,
	) -> Result<(Option<H160>, Option<H160>, CallOrCreateInfo), DispatchErrorWithPostInfo> {
		let transaction_data: TransactionData = transaction.into();
		let (weight_limit, proof_size_base_cost) = Self::transaction_weight(&transaction_data);
		let is_transactional = true;
		let validate = false;

		let (
			input,
			value,
			gas_limit,
			max_fee_per_gas,
			max_priority_fee_per_gas,
			nonce,
			action,
			access_list,
			authorization_list,
		) = {
			match transaction {
				// max_fee_per_gas and max_priority_fee_per_gas in legacy and 2930 transactions is
				// the provided gas_price.
				Transaction::Legacy(t) => (
					t.input.clone(),
					t.value,
					t.gas_limit,
					Some(t.gas_price),
					Some(t.gas_price),
					Some(t.nonce),
					t.action,
					Vec::new(),
					Vec::new(),
				),
				Transaction::EIP2930(t) => {
					let access_list: Vec<(H160, Vec<H256>)> = t
						.access_list
						.iter()
						.map(|item| (item.address, item.storage_keys.clone()))
						.collect();
					(
						t.input.clone(),
						t.value,
						t.gas_limit,
						Some(t.gas_price),
						Some(t.gas_price),
						Some(t.nonce),
						t.action,
						access_list,
						Vec::new(),
					)
				}
				Transaction::EIP1559(t) => {
					let access_list: Vec<(H160, Vec<H256>)> = t
						.access_list
						.iter()
						.map(|item| (item.address, item.storage_keys.clone()))
						.collect();
					(
						t.input.clone(),
						t.value,
						t.gas_limit,
						Some(t.max_fee_per_gas),
						Some(t.max_priority_fee_per_gas),
						Some(t.nonce),
						t.action,
						access_list,
						Vec::new(),
					)
				}
				Transaction::EIP7702(t) => {
					let access_list: Vec<(H160, Vec<H256>)> = t
						.access_list
						.iter()
						.map(|item| (item.address, item.storage_keys.clone()))
						.collect();
					(
						t.data.clone(),
						t.value,
						t.gas_limit,
						Some(t.max_fee_per_gas),
						Some(t.max_priority_fee_per_gas),
						Some(t.nonce),
						t.destination,
						access_list,
						t.authorization_list.clone(),
					)
				}
			}
		};

		match action {
			ethereum::TransactionAction::Call(target) => {
				let res = match T::Runner::call(
					from,
					target,
					input,
					value,
					gas_limit.unique_saturated_into(),
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
					authorization_list,
					is_transactional,
					validate,
					weight_limit,
					proof_size_base_cost,
					config.as_ref().unwrap_or_else(|| T::config()),
				) {
					Ok(res) => res,
					Err(e) => {
						return Err(DispatchErrorWithPostInfo {
							post_info: PostDispatchInfo {
								actual_weight: Some(e.weight),
								pays_fee: Pays::Yes,
							},
							error: e.error.into(),
						})
					}
				};

				Ok((Some(target), None, CallOrCreateInfo::Call(res)))
			}
			ethereum::TransactionAction::Create => {
				let res = if let Some(force_address) = maybe_force_create_address {
					match T::Runner::create_force_address(
						from,
						input,
						value,
						gas_limit.unique_saturated_into(),
						max_fee_per_gas,
						max_priority_fee_per_gas,
						nonce,
						access_list,
						authorization_list,
						is_transactional,
						validate,
						weight_limit,
						proof_size_base_cost,
						config.as_ref().unwrap_or_else(|| T::config()),
						force_address,
					) {
						Ok(res) => res,
						Err(e) => {
							return Err(DispatchErrorWithPostInfo {
								post_info: PostDispatchInfo {
									actual_weight: Some(e.weight),
									pays_fee: Pays::Yes,
								},
								error: e.error.into(),
							})
						}
					}
				} else {
					match T::Runner::create(
						from,
						input,
						value,
						gas_limit.unique_saturated_into(),
						max_fee_per_gas,
						max_priority_fee_per_gas,
						nonce,
						access_list,
						authorization_list,
						is_transactional,
						validate,
						weight_limit,
						proof_size_base_cost,
						config.as_ref().unwrap_or_else(|| T::config()),
					) {
						Ok(res) => res,
						Err(e) => {
							return Err(DispatchErrorWithPostInfo {
								post_info: PostDispatchInfo {
									actual_weight: Some(e.weight),
									pays_fee: Pays::Yes,
								},
								error: e.error.into(),
							})
						}
					}
				};

				Ok((None, Some(res.value), CallOrCreateInfo::Create(res)))
			}
		}
	}

	/// Validate an Ethereum transaction already in block
	///
	/// This function must be called during the pre-dispatch phase
	/// (just before applying the extrinsic).
	pub fn validate_transaction_in_block(
		origin: H160,
		transaction: &Transaction,
	) -> Result<(), TransactionValidityError> {
		let transaction_data: TransactionData = transaction.into();
		let (weight_limit, proof_size_base_cost) = Self::transaction_weight(&transaction_data);
		let (base_fee, _) = T::FeeCalculator::min_gas_price();
		let (who, _) = pallet_evm::Pallet::<T>::account_basic(&origin);

		// Check if this is an EIP-7702 transaction
		let is_eip7702 = matches!(transaction, Transaction::EIP7702(_));

		let _ = CheckEvmTransaction::<InvalidTransactionWrapper>::new(
			CheckEvmTransactionConfig {
				evm_config: T::config(),
				block_gas_limit: T::BlockGasLimit::get(),
				base_fee,
				chain_id: T::ChainId::get(),
				is_transactional: true,
			},
			transaction_data.into(),
			weight_limit,
			proof_size_base_cost,
		)
		.validate_in_block_for(&who)
		.and_then(|v| v.with_chain_id())
		.and_then(|v| v.with_base_fee())
		.and_then(|v| v.with_balance_for(&who))
		.and_then(|v| v.with_eip7702_authorization_list(is_eip7702))
		.map_err(|e| TransactionValidityError::Invalid(e.0))?;

		Ok(())
	}

	pub fn migrate_block_v0_to_v2() -> Weight {
		let db_weights = T::DbWeight::get();
		let mut weight: Weight = db_weights.reads(1);
		let item = b"CurrentBlock";
		let block_v0 = frame_support::storage::migration::get_storage_value::<ethereum::BlockV0>(
			Self::name().as_bytes(),
			item,
			&[],
		);
		if let Some(block_v0) = block_v0 {
			weight = weight.saturating_add(db_weights.writes(1));
			let block_v2: ethereum::BlockV2 = block_v0.into();
			frame_support::storage::migration::put_storage_value::<ethereum::BlockV2>(
				Self::name().as_bytes(),
				item,
				&[],
				block_v2,
			);
		}
		weight
	}

	#[cfg(feature = "try-runtime")]
	pub fn pre_migrate_block_v2() -> Result<Vec<u8>, &'static str> {
		let item = b"CurrentBlock";
		let block_v0 = frame_support::storage::migration::get_storage_value::<ethereum::BlockV0>(
			Self::name().as_bytes(),
			item,
			&[],
		);
		if let Some(block_v0) = block_v0 {
			Ok((
				block_v0.header.number,
				block_v0.header.parent_hash,
				block_v0.transactions.len() as u64,
			)
				.encode())
		} else {
			// No legacy BlockV0 present (fresh chain / already migrated). Return an
			// empty state so `post_migrate_block_v2` skips its assertions. Without this
			// `else` the function has no value on the None path and fails to compile
			// under `--features try-runtime` (E0317).
			Ok(Vec::new())
		}
	}

	#[cfg(feature = "try-runtime")]
	pub fn post_migrate_block_v2(v0_data: Vec<u8>) -> Result<(), &'static str> {
		// Empty state means `pre_migrate_block_v2` found no legacy BlockV0 (fresh chain
		// or already migrated), so there is nothing to assert against.
		if v0_data.is_empty() {
			return Ok(());
		}
		let (v0_number, v0_parent_hash, v0_transaction_len): (U256, H256, u64) = Decode::decode(
			&mut v0_data.as_slice(),
		)
		.map_err(|_| "the state parameter should be something that was generated by pre_upgrade")?;
		let item = b"CurrentBlock";
		let block_v2 = frame_support::storage::migration::get_storage_value::<ethereum::BlockV2>(
			Self::name().as_bytes(),
			item,
			&[],
		);

		let Some(block_v2) = block_v2 else {
			return Err("BlockV2 storage item missing post migration");
		};
		assert_eq!(block_v2.header.number, v0_number);
		assert_eq!(block_v2.header.parent_hash, v0_parent_hash);
		assert_eq!(block_v2.transactions.len() as u64, v0_transaction_len);
		Ok(())
	}
}

pub struct ValidatedTransaction<T>(PhantomData<T>);
impl<T: Config> ValidatedTransactionT for ValidatedTransaction<T> {
	fn apply(
		source: H160,
		transaction: Transaction,
		maybe_force_create_address: Option<H160>,
	) -> Result<(PostDispatchInfo, CallOrCreateInfo), DispatchErrorWithPostInfo> {
		Pallet::<T>::apply_validated_transaction(source, transaction, maybe_force_create_address)
	}
}

#[derive(Eq, PartialEq, Clone, RuntimeDebug)]
pub enum ReturnValue {
	Bytes(Vec<u8>),
	Hash(H160),
}

pub struct IntermediateStateRoot<T>(PhantomData<T>);
impl<T: Get<RuntimeVersion>> Get<H256> for IntermediateStateRoot<T> {
	fn get() -> H256 {
		let version = T::get().state_version();
		// CONSENSUS SAFETY: the storage root is produced by the same node that runs
		// this runtime, so it must always decode to a valid H256. If it does not, the
		// node's environment is fundamentally broken and continuing would embed a
		// garbage/zero state root into the block header — silently diverging from every
		// other validator. Halting here is the required fail-safe; returning a default
		// value would poison consensus. (Overrides crate-level `deny(expect_used)`.)
		#[allow(clippy::expect_used)]
		H256::decode(&mut &sp_io::storage::root(version)[..])
			.expect("Node is configured to use the same hash; qed")
	}
}

/// Returns the Ethereum block hash by number.
pub struct EthereumBlockHashMapping<T>(PhantomData<T>);
impl<T: Config> BlockHashMapping for EthereumBlockHashMapping<T> {
	fn block_hash(number: u32) -> H256 {
		BlockHash::<T>::get(U256::from(number))
	}
}

pub struct InvalidTransactionWrapper(InvalidTransaction);

impl From<TransactionValidationError> for InvalidTransactionWrapper {
	fn from(validation_error: TransactionValidationError) -> Self {
		match validation_error {
			TransactionValidationError::GasLimitTooLow => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::GasLimitTooLow as u8),
			),
			TransactionValidationError::GasLimitTooHigh => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::GasLimitTooHigh as u8),
			),
			TransactionValidationError::PriorityFeeTooHigh => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::PriorityFeeTooHigh as u8),
			),
			TransactionValidationError::BalanceTooLow => {
				InvalidTransactionWrapper(InvalidTransaction::Payment)
			}
			TransactionValidationError::TxNonceTooLow => {
				InvalidTransactionWrapper(InvalidTransaction::Stale)
			}
			TransactionValidationError::TxNonceTooHigh => {
				InvalidTransactionWrapper(InvalidTransaction::Future)
			}
			TransactionValidationError::InvalidFeeInput => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::InvalidFeeInput as u8),
			),
			TransactionValidationError::InvalidChainId => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::InvalidChainId as u8),
			),
			TransactionValidationError::InvalidSignature => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::InvalidSignature as u8),
			),
			TransactionValidationError::GasPriceTooLow => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::GasPriceTooLow as u8),
			),
			TransactionValidationError::EmptyAuthorizationList => {
				InvalidTransactionWrapper(InvalidTransaction::Custom(
					TransactionValidationError::EmptyAuthorizationList as u8,
				))
			}
			TransactionValidationError::AuthorizationListTooLarge => {
				InvalidTransactionWrapper(InvalidTransaction::Custom(
					TransactionValidationError::AuthorizationListTooLarge as u8,
				))
			}
			TransactionValidationError::UnknownError => InvalidTransactionWrapper(
				InvalidTransaction::Custom(TransactionValidationError::UnknownError as u8),
			),
		}
	}
}
