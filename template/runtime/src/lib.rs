//! The Substrate Node Template runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]
#![allow(clippy::new_without_default, clippy::or_fun_call)]
#![cfg_attr(feature = "runtime-benchmarks", warn(unused_crate_dependencies))]

extern crate alloc;

mod genesis_config_preset;
mod precompiles;
mod weights;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use alloc::{borrow::Cow, vec, vec::Vec};
use core::marker::PhantomData;
use ethereum::AuthorizationList;
use scale_codec::{Decode, Encode};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::{AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use sp_core::{
	crypto::{ByteArray, KeyTypeId},
	ConstU128, OpaqueMetadata, H160, H256, U256,
};
use sp_runtime::{
	generic, impl_opaque_keys,
	traits::{
		BlakeTwo256, Block as BlockT, DispatchInfoOf, Dispatchable, Get, IdentifyAccount,
		IdentityLookup, NumberFor, PostDispatchInfoOf, UniqueSaturatedInto, Verify,
	},
	transaction_validity::{TransactionSource, TransactionValidity, TransactionValidityError},
	ApplyExtrinsicResult, ConsensusEngineId, ExtrinsicInclusionMode, Perbill, Permill,
};
use sp_version::RuntimeVersion;
// Substrate FRAME
#[cfg(feature = "with-paritydb-weights")]
use frame_support::weights::constants::ParityDbWeight as RuntimeDbWeight;
#[cfg(feature = "with-rocksdb-weights")]
use frame_support::weights::constants::RocksDbWeight as RuntimeDbWeight;
use frame_support::{
	derive_impl,
	genesis_builder_helper::build_state,
	parameter_types,
	traits::{ConstBool, ConstU32, ConstU64, ConstU8, FindAuthor, OnFinalize, OnTimestampSet},
	weights::{constants::WEIGHT_REF_TIME_PER_MILLIS, IdentityFee, Weight},
};
use pallet_transaction_payment::FungibleAdapter;
use polkadot_runtime_common::SlowAdjustingFeeUpdate;
use sp_genesis_builder::PresetId;
// Frontier
use fp_account::PqcSignature;
use fp_evm::weight_per_gas;
use fp_rpc::TransactionStatus;
use pallet_ethereum::{Call::transact, PostLogContent, Transaction as EthereumTransaction};
use pallet_evm::{
	Account as EVMAccount, EnsureAccountId20, FeeCalculator, IdentityAddressMapping, Runner,
};

// A few exports that help ease life for downstream crates.
pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;

use precompiles::FrontierPrecompiles;

/// Type of block number.
pub type BlockNumber = u32;

/// The runtime signature type. On a BlackChain network this is the composite
/// post-quantum signature, so EVERY signed Substrate extrinsic (any pallet call)
/// is authenticated by the hybrid PQC verifier at the single `Verify` choke point.
pub type Signature = PqcSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// The type for looking up accounts. We don't expect more than 4 billion of them, but you
/// never know...
pub type AccountIndex = u32;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = H256;

/// The hashing algorithm used by the chain.
pub type Hashing = BlakeTwo256;

/// Digest item type.
pub type DigestItem = generic::DigestItem;

/// The address format for describing accounts.
pub type Address = AccountId;

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = cumulus_pallet_weight_reclaim::StorageWeightReclaim<
	Runtime,
	(
		frame_system::CheckNonZeroSender<Runtime>,
		frame_system::CheckSpecVersion<Runtime>,
		frame_system::CheckTxVersion<Runtime>,
		frame_system::CheckGenesis<Runtime>,
		frame_system::CheckEra<Runtime>,
		frame_system::CheckNonce<Runtime>,
		frame_system::CheckWeight<Runtime>,
		pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
		// Charges every signed extrinsic the weight of the composite PQC signature
		// verification (which runs in `check()`, outside the call/extension weights).
		pqc_verify_weight::ChargePqcVerify<Runtime>,
	),
>;

/// Transaction extension that accounts the weight of the composite PQC signature
/// verification for the signed-extrinsic path.
pub mod pqc_verify_weight {
	use core::marker::PhantomData;
	use frame_support::{weights::Weight, DefaultNoBound};
	use scale_codec::{Decode, DecodeWithMemTracking, Encode};
	use scale_info::TypeInfo;
	use sp_runtime::{
		impl_tx_ext_default,
		traits::{DispatchInfoOf, TransactionExtension},
		transaction_validity::TransactionSource,
	};

	/// Benchmarked cost of ONE composite verification (ML-DSA-87 + P-521 + Ed448).
	/// PLACEHOLDER (~1.6 ms of ref_time) — replace with a measured benchmark
	/// (Phase 5). This is a safe *serial* upper bound: it bounds how many PQC-signed
	/// extrinsics fit a block's weight budget; the parallel import pre-pass is what
	/// lets a node actually verify that many within the slot.
	pub const PQC_VERIFY_REF_TIME: u64 = 1_600_000_000;

	/// No-op transaction extension that only contributes `PQC_VERIFY_REF_TIME` to
	/// each signed extrinsic's weight. Self-contained calls carry no extensions, so
	/// this applies ONLY to the signed-extrinsic path (no double-counting with the
	/// EVM/sudo/transfer paths, which weigh their verify in their own call weight).
	#[derive(Encode, Decode, DecodeWithMemTracking, DefaultNoBound, Clone, Eq, PartialEq, TypeInfo)]
	#[scale_info(skip_type_params(T))]
	pub struct ChargePqcVerify<T>(PhantomData<T>);

	impl<T> ChargePqcVerify<T> {
		pub fn new() -> Self {
			Self(PhantomData)
		}
	}

	impl<T> core::fmt::Debug for ChargePqcVerify<T> {
		fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
			write!(f, "ChargePqcVerify")
		}
	}

	impl<T: frame_system::Config + Send + Sync> TransactionExtension<T::RuntimeCall>
		for ChargePqcVerify<T>
	{
		const IDENTIFIER: &'static str = "ChargePqcVerify";
		type Implicit = ();
		type Val = ();
		type Pre = ();

		fn weight(&self, _: &T::RuntimeCall) -> Weight {
			Weight::from_parts(PQC_VERIFY_REF_TIME, 0)
		}

		fn validate(
			&self,
			origin: T::RuntimeOrigin,
			_call: &T::RuntimeCall,
			_info: &DispatchInfoOf<T::RuntimeCall>,
			_len: usize,
			_self_implicit: Self::Implicit,
			_inherited_implication: &impl Encode,
			_source: TransactionSource,
		) -> sp_runtime::traits::ValidateResult<Self::Val, T::RuntimeCall> {
			Ok((Default::default(), (), origin))
		}

		impl_tx_ext_default!(T::RuntimeCall; prepare);
	}
}

/// Std-only helpers for an off-chain client to build a PQC-signed extrinsic.
///
/// A client cannot call each extension's `implicit()` (those read chain state), so
/// it queries the implicit values over RPC (spec/tx version, genesis hash) and
/// hands them here. This keeps the finicky `SignedExtra`/`SignedPayload` type
/// construction next to the types, so a client only needs this crate.
#[cfg(feature = "std")]
pub mod client {
	use super::{
		AccountId, Balance, Hash, RuntimeCall, SignedExtra, SignedPayload, UncheckedExtrinsic,
	};
	use scale_codec::Encode;
	use sp_runtime::generic::Era;

	/// Build a native `Balances::transfer_allow_death` call.
	pub fn balances_transfer_call(dest: AccountId, value: Balance) -> RuntimeCall {
		RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death { dest, value })
	}

	/// Build the immortal `SignedExtra` for `nonce`/`tip`, and the EXACT bytes a
	/// client must PQC-sign (`BLACKCHAIN_EXTRINSIC_V1 ‖ signed-payload`, with the
	/// >256-byte blake2 rule already applied by `using_encoded`).
	pub fn signing_message(
		call: &RuntimeCall,
		nonce: u32,
		tip: Balance,
		spec_version: u32,
		tx_version: u32,
		genesis_hash: Hash,
	) -> (SignedExtra, Vec<u8>) {
		let extra = cumulus_pallet_weight_reclaim::StorageWeightReclaim::new((
			frame_system::CheckNonZeroSender::new(),
			frame_system::CheckSpecVersion::new(),
			frame_system::CheckTxVersion::new(),
			frame_system::CheckGenesis::new(),
			frame_system::CheckEra::from(Era::Immortal),
			frame_system::CheckNonce::from(nonce),
			frame_system::CheckWeight::new(),
			pallet_transaction_payment::ChargeTransactionPayment::from(tip),
			super::pqc_verify_weight::ChargePqcVerify::new(),
		));
		// Implicit (additional-signed) values for an immortal extrinsic. The empty
		// tuples are the extensions whose implicit is `()`; era (immortal) binds to
		// the genesis hash.
		let implicit = (
			(),
			spec_version,
			tx_version,
			genesis_hash,
			genesis_hash,
			(),
			(),
			(),
			(),
		);
		let payload = SignedPayload::from_raw(call.clone(), extra.clone(), implicit);
		let msg = payload.using_encoded(|p| {
			let mut m = fp_account::EXTRINSIC_DOMAIN_TAG.to_vec();
			m.extend_from_slice(p);
			m
		});
		(extra, msg)
	}

	/// Assemble the signed `UncheckedExtrinsic` from a composite PQC signature.
	pub fn assemble(
		call: RuntimeCall,
		sender: AccountId,
		pub_key: Vec<u8>,
		signature: Vec<u8>,
		extra: SignedExtra,
	) -> UncheckedExtrinsic {
		UncheckedExtrinsic::new_signed(
			call,
			sender,
			fp_account::PqcSignature::new(pub_key, signature),
			extra,
		)
	}
}

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	fp_self_contained::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic =
	fp_self_contained::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra, H160>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
>;

// Time is measured by number of blocks.
pub const MILLISECS_PER_BLOCK: u64 = 2000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
	use super::*;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;

	impl_opaque_keys! {
		pub struct SessionKeys {
			pub aura: Aura,
			pub grandpa: Grandpa,
		}
	}
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: Cow::Borrowed("frontier-template"),
	impl_name: Cow::Borrowed("frontier-template"),
	authoring_version: 1,
	spec_version: 2,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	system_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> sp_version::NativeVersion {
	sp_version::NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// 2000ms of compute budget in a 2 second block. This is the *full* slot: it is a
/// throughput-experiment / dev operating point that leans on the parallel import
/// pre-pass (`pqc_prewarm`) to keep wall-clock verify well under the slot, and on
/// manual/dev sealing (no real propagation deadline). A production multi-node setup
/// would reserve part of the slot for block propagation (e.g. 1/3, as 6s/2000ms did).
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
	WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS,
	u64::MAX,
);
// 18 MiB blocks. Bounded by the WASM executor, not consensus: finalize_block builds
// the extrinsics-root by SCALE-encoding the whole block body into one Vec, which
// grows by DOUBLING, so a body over ~16 MiB forces a 32 MiB allocation that exceeds
// sp-core's hard MAX_POSSIBLE_ALLOCATION (32 MiB) → "Requested allocation size is too
// large" panic in finalize_block. Measured live: 13.8 MiB body (1792 txs) seals; 22
// MiB (3000) and 54 MiB (7000) panic. 18 MiB keeps normal-class 75% (13.5 MiB) at the
// proven-safe point → ~1800 of the ~7.7 KB PQC extrinsics. To go higher you must
// SHRINK the signature (e.g. on-chain pubkey registry: 7.7 KB → ~4.9 KB), not raise
// this. (ChargePqcVerify's 1.6ms weight does NOT bind — it is a no-op extension whose
// declared weight is reclaimed as unused, so block LENGTH is the ceiling.)
pub const MAXIMUM_BLOCK_LENGTH: u32 = 18 * 1024 * 1024;

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const BlockHashCount: BlockNumber = 256;
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
		::with_sensible_defaults(MAXIMUM_BLOCK_WEIGHT, NORMAL_DISPATCH_RATIO);
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
		::max_with_normal_ratio(MAXIMUM_BLOCK_LENGTH, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 42;
}

// Configure FRAME pallets to include in runtime.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Runtime {
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = BlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = BlockLength;
	/// The index type for storing how many extrinsics an account has signed.
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = Hashing;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = IdentityLookup<AccountId>;
	/// The block type.
	type Block = Block;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RuntimeDbWeight;
	/// Version of the runtime.
	type Version = Version;
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = ConstU32<16>;
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = ConstU32<32>;
	type DisabledValidators = ();
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}

impl cumulus_pallet_weight_reclaim::Config for Runtime {
	type WeightInfo = ();
}

parameter_types! {
	pub storage EnableManualSeal: bool = false;
}

pub struct ConsensusOnTimestampSet<T>(PhantomData<T>);
impl<T: pallet_aura::Config> OnTimestampSet<T::Moment> for ConsensusOnTimestampSet<T> {
	fn on_timestamp_set(moment: T::Moment) {
		if EnableManualSeal::get() {
			return;
		}
		<pallet_aura::Pallet<T> as OnTimestampSet<T::Moment>>::on_timestamp_set(moment)
	}
}

impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = ConsensusOnTimestampSet<Self>;
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type WeightInfo = ();
}

pub const EXISTENTIAL_DEPOSIT: u128 = 0;

impl pallet_balances::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Self>;
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ConstU32<50>;
	type MaxFreezes = ConstU32<1>;
	type DoneSlashHandler = ();
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = FungibleAdapter<Balances, ()>;
	type WeightToFee = IdentityFee<Balance>;
	type LengthToFee = IdentityFee<Balance>;
	/// Parameterized slow adjusting fee updated based on
	/// <https://research.web3.foundation/Polkadot/overview/token-economics#2-slow-adjusting-mechanism>
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Runtime>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Self>;
}

impl pallet_evm_chain_id::Config for Runtime {}

impl pallet_blackchain_sudo::Config for Runtime {
	type RuntimeCall = RuntimeCall;
	// Bind admin signatures to this chain's id (same value as the EVM chain id),
	// preventing cross-chain replay of privileged calls.
	type ChainId = <Self as pallet_evm::Config>::ChainId;
}

pub struct FindAuthorTruncated<F>(PhantomData<F>);
impl<F: FindAuthor<u32>> FindAuthor<H160> for FindAuthorTruncated<F> {
	fn find_author<'a, I>(digests: I) -> Option<H160>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		if let Some(author_index) = F::find_author(digests) {
			let authority_id =
				pallet_aura::Authorities::<Runtime>::get()[author_index as usize].clone();
			return Some(H160::from_slice(&authority_id.to_raw_vec()[4..24]));
		}
		None
	}
}

const BLOCK_GAS_LIMIT: u64 = 75_000_000;
const MAX_POV_SIZE: u64 = 5 * 1024 * 1024;
/// The maximum storage growth per block in bytes.
const MAX_STORAGE_GROWTH: u64 = 400 * 1024;

// ---------------------------------------------------------------------------
// BlackChain PQC block capacity analysis
// ---------------------------------------------------------------------------
//
// Each BlackChain PQC transaction carries significant fixed payload overhead:
//   pqc_signature  : ~4,841 bytes  (Dilithium5 ‖ P-521 ‖ Ed448)
//   pub_key        : ~2,782 bytes  (Dilithium5 ‖ P-521 ‖ Ed448 public keys)
//   ---
//   fixed overhead : ~7,623 bytes per transaction (before ABI/SCALE framing)
//
// PoV-limit throughput (with 5 MB PoV, ~7.6 KB/tx overhead):
//   MAX_POV_SIZE / 7_623 ≈ 655 PQC txs/block (upper bound, ignoring headers)
//
// Gas-limit throughput (with 75M gas limit, 21,000 gas/simple transfer):
//   BLOCK_GAS_LIMIT / 21_000 ≈ 3,571 txs (this is NOT the binding constraint)
//
// The binding constraint for PQC txs is the PoV size, not gas.
// With the default settings this chain can process roughly 600–650 simple PQC
// value-transfer transactions per block.
//
// TODO before mainnet:
//   1. Measure actual PQC tx serialised size on a loaded block.
//   2. Run throughput tests to determine real block capacity.
//   3. Consider increasing MAX_POV_SIZE or implementing batching if needed.
//   4. Model propagation latency for blocks full of 7.6 KB transactions.
const PQC_SIG_BYTES: u64 = 4_841;
const PQC_PK_BYTES: u64 = 2_782;
/// Approximate fixed payload overhead per PQC transaction in bytes.
pub const PQC_TX_PAYLOAD_BYTES: u64 = PQC_SIG_BYTES + PQC_PK_BYTES;
/// Approximate maximum PQC transactions per block (PoV-limited, not gas-limited).
pub const PQC_MAX_TXS_PER_BLOCK_POV: u64 = MAX_POV_SIZE / PQC_TX_PAYLOAD_BYTES;

parameter_types! {
	pub BlockGasLimit: U256 = U256::from(BLOCK_GAS_LIMIT);
	pub const GasLimitPovSizeRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_POV_SIZE);
	pub const GasLimitStorageGrowthRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_STORAGE_GROWTH);
	pub PrecompilesValue: FrontierPrecompiles<Runtime> = FrontierPrecompiles::<_>::new();
	pub WeightPerGas: Weight = Weight::from_parts(weight_per_gas(BLOCK_GAS_LIMIT, NORMAL_DISPATCH_RATIO, WEIGHT_MILLISECS_PER_BLOCK), 0);
}

impl pallet_evm::Config for Runtime {
	type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
	type FeeCalculator = BaseFee;
	type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
	type WeightPerGas = WeightPerGas;
	type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
	type CallOrigin = EnsureAccountId20;
	type WithdrawOrigin = EnsureAccountId20;
	type AddressMapping = IdentityAddressMapping;
	type Currency = Balances;
	type PrecompilesType = FrontierPrecompiles<Self>;
	type PrecompilesValue = PrecompilesValue;
	type ChainId = EVMChainId;
	type BlockGasLimit = BlockGasLimit;
	type Runner = pallet_evm::runner::stack::Runner<Self>;
	type OnChargeTransaction = ();
	type OnCreate = ();
	type FindAuthor = FindAuthorTruncated<Aura>;
	type GasLimitPovSizeRatio = GasLimitPovSizeRatio;
	type GasLimitStorageGrowthRatio = GasLimitStorageGrowthRatio;
	type Timestamp = Timestamp;
	type CreateOriginFilter = ();
	type CreateInnerOriginFilter = ();
	type WeightInfo = pallet_evm::weights::SubstrateWeight<Self>;
}

parameter_types! {
	pub const PostBlockAndTxnHashes: PostLogContent = PostLogContent::BlockAndTxnHashes;
}

impl pallet_ethereum::Config for Runtime {
	type StateRoot = pallet_ethereum::IntermediateStateRoot<Self::Version>;
	type PostLogContent = PostBlockAndTxnHashes;
	type ExtraDataLength = ConstU32<30>;
	/// Use benchmarked weights for PQC signature verification.
	///
	/// `SubstrateWeight<Runtime>` reads its values from `frame/ethereum/src/weights.rs`.
	/// Run the benchmark command in that file's doc-comment to populate it with real numbers.
	type BlackChainWeightInfo = pallet_ethereum::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub BoundDivision: U256 = U256::from(1024);
}

impl pallet_dynamic_fee::Config for Runtime {
	type MinGasPriceBoundDivisor = BoundDivision;
}

parameter_types! {
	pub DefaultBaseFeePerGas: U256 = U256::from(1_000_000_000);
	pub DefaultElasticity: Permill = Permill::from_parts(125_000);
}
pub struct BaseFeeThreshold;
impl pallet_base_fee::BaseFeeThreshold for BaseFeeThreshold {
	fn lower() -> Permill {
		Permill::zero()
	}
	fn ideal() -> Permill {
		Permill::from_parts(500_000)
	}
	fn upper() -> Permill {
		Permill::from_parts(1_000_000)
	}
}
impl pallet_base_fee::Config for Runtime {
	type Threshold = BaseFeeThreshold;
	type DefaultBaseFeePerGas = DefaultBaseFeePerGas;
	type DefaultElasticity = DefaultElasticity;
}

#[frame_support::pallet]
pub mod pallet_manual_seal {
	use super::*;
	use frame_support::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T> {
		pub enable: bool,
		#[serde(skip)]
		pub _config: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			EnableManualSeal::set(&self.enable);
		}
	}
}

impl pallet_manual_seal::Config for Runtime {}

// Create the runtime by composing the FRAME pallets that were previously configured.
#[frame_support::runtime]
mod runtime {
	#[runtime::runtime]
	#[runtime::derive(
		RuntimeEvent,
		RuntimeCall,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask
	)]
	pub struct Runtime;

	#[runtime::pallet_index(0)]
	pub type System = frame_system;

	#[runtime::pallet_index(1)]
	pub type Timestamp = pallet_timestamp;

	#[runtime::pallet_index(2)]
	pub type Aura = pallet_aura;

	#[runtime::pallet_index(3)]
	pub type Grandpa = pallet_grandpa;

	#[runtime::pallet_index(4)]
	pub type Balances = pallet_balances;

	#[runtime::pallet_index(5)]
	pub type TransactionPayment = pallet_transaction_payment;

	#[runtime::pallet_index(6)]
	pub type Sudo = pallet_sudo;

	#[runtime::pallet_index(7)]
	pub type Ethereum = pallet_ethereum;

	#[runtime::pallet_index(8)]
	pub type EVM = pallet_evm;

	#[runtime::pallet_index(9)]
	pub type EVMChainId = pallet_evm_chain_id;

	#[runtime::pallet_index(10)]
	pub type BaseFee = pallet_base_fee;

	#[runtime::pallet_index(11)]
	pub type ManualSeal = pallet_manual_seal;

	// PQC-authenticated admin path: dispatches Root calls (set_code, governance,
	// key rotation) authorised by a composite Dilithium5+P-521+Ed448 signature,
	// since classic signed extrinsics — and therefore pallet-sudo — are disabled.
	#[runtime::pallet_index(12)]
	pub type BlackchainSudo = pallet_blackchain_sudo;
}

#[derive(Clone)]
pub struct TransactionConverter<B>(PhantomData<B>);

impl<B> Default for TransactionConverter<B> {
	fn default() -> Self {
		Self(PhantomData)
	}
}

impl<B: BlockT> fp_rpc::ConvertTransaction<<B as BlockT>::Extrinsic> for TransactionConverter<B> {
	fn convert_transaction(
		&self,
		transaction: pallet_ethereum::Transaction,
	) -> <B as BlockT>::Extrinsic {
		let extrinsic = UncheckedExtrinsic::new_bare(
			pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
		);
		let encoded = extrinsic.encode();
		<B as BlockT>::Extrinsic::decode(&mut &encoded[..])
			.expect("Encoded extrinsic is always valid")
	}
}

impl fp_self_contained::SelfContainedCall for RuntimeCall {
	type SignedInfo = H160;

	fn is_self_contained(&self) -> bool {
		match self {
			RuntimeCall::Ethereum(call) => call.is_self_contained(),
			RuntimeCall::BlackchainSudo(call) => call.is_self_contained(),
			_ => false,
		}
	}

	fn check_self_contained(&self) -> Option<Result<Self::SignedInfo, TransactionValidityError>> {
		match self {
			RuntimeCall::Ethereum(call) => call.check_self_contained(),
			RuntimeCall::BlackchainSudo(call) => call.check_self_contained(),
			_ => None,
		}
	}

	fn validate_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		len: usize,
	) -> Option<TransactionValidity> {
		match self {
			RuntimeCall::Ethereum(call) => call.validate_self_contained(info, dispatch_info, len),
			RuntimeCall::BlackchainSudo(call) => {
				call.validate_self_contained(info, dispatch_info, len)
			}
			_ => None,
		}
	}

	fn pre_dispatch_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		len: usize,
	) -> Option<Result<(), TransactionValidityError>> {
		match self {
			RuntimeCall::Ethereum(call) => {
				call.pre_dispatch_self_contained(info, dispatch_info, len)
			}
			RuntimeCall::BlackchainSudo(call) => {
				call.pre_dispatch_self_contained(info, dispatch_info, len)
			}
			_ => None,
		}
	}

	fn apply_self_contained(
		self,
		info: Self::SignedInfo,
	) -> Option<sp_runtime::DispatchResultWithInfo<PostDispatchInfoOf<Self>>> {
		match self {
			call @ RuntimeCall::Ethereum(pallet_ethereum::Call::transact { .. }) => {
				Some(call.dispatch(RuntimeOrigin::from(
					pallet_ethereum::RawOrigin::EthereumTransaction(info),
				)))
			}
			call @ RuntimeCall::Ethereum(pallet_ethereum::Call::transact_blackchain { .. }) => {
				Some(call.dispatch(RuntimeOrigin::from(
					pallet_ethereum::RawOrigin::EthereumTransaction(info),
				)))
			}
			// PQC-authenticated admin call: dispatch with the verified admin origin,
			// which the pallet's `sudo` then elevates to `Root` after checking the
			// configured admin key and nonce.
			call @ RuntimeCall::BlackchainSudo(pallet_blackchain_sudo::Call::sudo { .. }) => {
				Some(call.dispatch(RuntimeOrigin::from(
					pallet_blackchain_sudo::RawOrigin::BlackchainAdmin(info),
				)))
			}
			_ => None,
		}
	}
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
	frame_benchmarking::define_benchmarks!(
		[frame_benchmarking, BaselineBench::<Runtime>]
		[frame_system, SystemBench::<Runtime>]
		[pallet_balances, Balances]
		[pallet_timestamp, Timestamp]
		[pallet_sudo, Sudo]
		[pallet_evm, EVM]
		[pallet_evm_precompile_curve25519, EVMPrecompileCurve25519Bench::<Runtime>]
		[pallet_evm_precompile_sha3fips, EVMPrecompileSha3FIPSBench::<Runtime>]
		[pallet_ethereum, Ethereum]
	);
}

/// CR-2 pre-filter for the PQC signed-extrinsic path.
///
/// A composite PQC verification costs ~1.6 ms and, for a signed extrinsic, runs
/// inside `check()` BEFORE the fee/nonce extensions — so an attacker could flood
/// valid-length garbage signatures and burn CPU for free. The claimed sender is
/// carried IN the extrinsic (the `Signed` preamble) and is readable WITHOUT
/// verifying, so an unfunded claimed sender is dropped here, before the verify is
/// ever paid for. This chain's existential deposit is 0, so the meaningful cheap
/// test is a zero free balance — a random/garbage key derives an unfunded address
/// and is rejected. (Self-contained calls use `Bare`/`General` preambles and keep
/// their own pre-filter in `check_self_contained`, so they are unaffected.)
fn pqc_signed_prefilter(tx: &UncheckedExtrinsic) -> Result<(), TransactionValidityError> {
	use sp_runtime::{generic::Preamble, transaction_validity::InvalidTransaction};
	if let Preamble::Signed(address, _, _) = &tx.0.preamble {
		let free = frame_system::Account::<Runtime>::get(address).data.free;
		if free == 0 {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Payment));
		}
	}
	Ok(())
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: <Block as BlockT>::LazyBlock) {
			Executive::execute_block(block)
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: <Block as BlockT>::LazyBlock,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			// CR-2 pre-filter runs BEFORE the ~1.6 ms PQC verify (see
			// `pqc_signed_prefilter`), dropping unfunded garbage-signature spam.
			pqc_signed_prefilter(&tx)?;
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<PresetId>) -> Option<Vec<u8>> {
			frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(id, genesis_config_preset::get_preset)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			vec![PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET)]
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			opaque::SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
		}

		fn authorities() -> Vec<AuraId> {
			pallet_aura::Authorities::<Runtime>::get().into_inner()
		}
	}

	impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> GrandpaAuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> sp_consensus_grandpa::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			_equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			_key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			None
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			_authority_id: GrandpaId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			// NOTE: this is the only implementation possible since we've
			// defined our key owner proof type as a bottom type (i.e. a type
			// with no values).
			None
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		Balance,
	> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}

		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}

		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}

		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl fp_rpc::EthereumRuntimeRPCApi<Block> for Runtime {
		fn chain_id() -> u64 {
			<Runtime as pallet_evm::Config>::ChainId::get()
		}

		fn account_basic(address: H160) -> EVMAccount {
			let (account, _) = pallet_evm::Pallet::<Runtime>::account_basic(&address);
			account
		}

		fn gas_price() -> U256 {
			let (gas_price, _) = <Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price();
			gas_price
		}

		fn account_code_at(address: H160) -> Vec<u8> {
			pallet_evm::AccountCodes::<Runtime>::get(address)
		}

		fn author() -> H160 {
			<pallet_evm::Pallet<Runtime>>::find_author()
		}

		fn storage_at(address: H160, index: U256) -> H256 {
			pallet_evm::AccountStorages::<Runtime>::get(address, H256::from(index.to_big_endian()))
		}

		fn call(
			from: H160,
			to: H160,
			data: Vec<u8>,
			value: U256,
			gas_limit: U256,
			max_fee_per_gas: Option<U256>,
			max_priority_fee_per_gas: Option<U256>,
			nonce: Option<U256>,
			estimate: bool,
			access_list: Option<Vec<(H160, Vec<H256>)>>,
			authorization_list: Option<AuthorizationList>,
		) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
			use pallet_evm::GasWeightMapping as _;

			let config = if estimate {
				let mut config = <Runtime as pallet_evm::Config>::config().clone();
				config.estimate = true;
				Some(config)
			} else {
				None
			};

			// Estimated encoded transaction size must be based on the heaviest transaction
			// type (EIP7702Transaction) to be compatible with all transaction types.
			let mut estimated_transaction_len = data.len() +
				// pallet ethereum index: 1
				// transact call index: 1
				// Transaction enum variant: 1
				// chain_id 8 bytes
				// nonce: 32
				// max_priority_fee_per_gas: 32
				// max_fee_per_gas: 32
				// gas_limit: 32
				// action: 21 (enum varianrt + call address)
				// value: 32
				// access_list: 1 (empty vec size)
				// authorization_list: 1 (empty vec size)
				// 65 bytes signature
				259;

			if access_list.is_some() {
				estimated_transaction_len += access_list.encoded_size();
			}

			if authorization_list.is_some() {
				estimated_transaction_len += authorization_list.encoded_size();
			}

			let gas_limit = if gas_limit > U256::from(u64::MAX) {
				u64::MAX
			} else {
				gas_limit.low_u64()
			};
			let without_base_extrinsic_weight = true;

			let (weight_limit, proof_size_base_cost) =
				match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
					gas_limit,
					without_base_extrinsic_weight
				) {
					weight_limit if weight_limit.proof_size() > 0 => {
						(Some(weight_limit), Some(estimated_transaction_len as u64))
					}
					_ => (None, None),
				};

			<Runtime as pallet_evm::Config>::Runner::call(
				from,
				to,
				data,
				value,
				gas_limit.unique_saturated_into(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				weight_limit,
				proof_size_base_cost,
				config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
			).map_err(|err| err.error.into())
		}

		fn create(
			from: H160,
			data: Vec<u8>,
			value: U256,
			gas_limit: U256,
			max_fee_per_gas: Option<U256>,
			max_priority_fee_per_gas: Option<U256>,
			nonce: Option<U256>,
			estimate: bool,
			access_list: Option<Vec<(H160, Vec<H256>)>>,
			authorization_list: Option<AuthorizationList>,
		) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
			use pallet_evm::GasWeightMapping as _;

			let config = if estimate {
				let mut config = <Runtime as pallet_evm::Config>::config().clone();
				config.estimate = true;
				Some(config)
			} else {
				None
			};


			let mut estimated_transaction_len = data.len() +
				// from: 20
				// value: 32
				// gas_limit: 32
				// nonce: 32
				// 1 byte transaction action variant
				// chain id 8 bytes
				// 65 bytes signature
				190;

			if max_fee_per_gas.is_some() {
				estimated_transaction_len += 32;
			}
			if max_priority_fee_per_gas.is_some() {
				estimated_transaction_len += 32;
			}
			if access_list.is_some() {
				estimated_transaction_len += access_list.encoded_size();
			}
			if authorization_list.is_some() {
				estimated_transaction_len += authorization_list.encoded_size();
			}

			let gas_limit = if gas_limit > U256::from(u64::MAX) {
				u64::MAX
			} else {
				gas_limit.low_u64()
			};
			let without_base_extrinsic_weight = true;

			let (weight_limit, proof_size_base_cost) =
				match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
					gas_limit,
					without_base_extrinsic_weight
				) {
					weight_limit if weight_limit.proof_size() > 0 => {
						(Some(weight_limit), Some(estimated_transaction_len as u64))
					}
					_ => (None, None),
				};

			<Runtime as pallet_evm::Config>::Runner::create(
				from,
				data,
				value,
				gas_limit.unique_saturated_into(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				weight_limit,
				proof_size_base_cost,
				config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
			).map_err(|err| err.error.into())
		}

		fn current_transaction_statuses() -> Option<Vec<TransactionStatus>> {
			pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
		}

		fn current_block() -> Option<pallet_ethereum::Block> {
			pallet_ethereum::CurrentBlock::<Runtime>::get()
		}

		fn current_receipts() -> Option<Vec<pallet_ethereum::Receipt>> {
			pallet_ethereum::CurrentReceipts::<Runtime>::get()
		}

		fn current_all() -> (
			Option<pallet_ethereum::Block>,
			Option<Vec<pallet_ethereum::Receipt>>,
			Option<Vec<TransactionStatus>>
		) {
			(
				pallet_ethereum::CurrentBlock::<Runtime>::get(),
				pallet_ethereum::CurrentReceipts::<Runtime>::get(),
				pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
			)
		}

		fn extrinsic_filter(
			xts: Vec<<Block as BlockT>::Extrinsic>,
		) -> Vec<EthereumTransaction> {
			xts.into_iter().filter_map(|xt| match xt.0.function {
				RuntimeCall::Ethereum(transact { transaction }) => Some(transaction),
				// Include BlackChain PQC transactions so pending-state RPCs
				// (eth_pendingTransactions, txpool_content, and the pre-mining
				// eth_getTransactionByHash fallback) surface them instead of dropping
				// them. Convert to the same derived EIP-1559 form used at execution
				// (`blackchain_to_evm_transaction`), so the hash seen while pending is
				// identical to the hash once the transaction is mined.
				RuntimeCall::Ethereum(pallet_ethereum::Call::transact_blackchain { transaction }) =>
					pallet_ethereum::Pallet::<Runtime>::blackchain_to_evm_transaction(&transaction),
				_ => None
			}).collect::<Vec<EthereumTransaction>>()
		}

		fn elasticity() -> Option<Permill> {
			Some(pallet_base_fee::Elasticity::<Runtime>::get())
		}

		fn gas_limit_multiplier_support() {}

		fn pending_block(
			xts: Vec<<Block as BlockT>::Extrinsic>,
		) -> (Option<pallet_ethereum::Block>, Option<Vec<TransactionStatus>>) {
			for ext in xts.into_iter() {
				let _ = Executive::apply_extrinsic(ext);
			}

			Ethereum::on_finalize(System::block_number() + 1);

			(
				pallet_ethereum::CurrentBlock::<Runtime>::get(),
				pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
			)
		}

		fn initialize_pending_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header);
		}
	}

	impl fp_rpc::ConvertTransactionRuntimeApi<Block> for Runtime {
		fn convert_transaction(transaction: EthereumTransaction) -> <Block as BlockT>::Extrinsic {
			UncheckedExtrinsic::new_bare(
				pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
			)
		}
	}

	impl fp_blackchain_rpc::BlackChainApi<Block> for Runtime {
		fn blackchain_tx_info(
			extrinsic: Vec<u8>,
		) -> Option<(H256, H160, Vec<u8>, Vec<u8>)> {
			// Decode a single bare extrinsic and, if it is a `transact_blackchain`
			// call, return (ethereum_hash, sender, composite_pub_key, composite_sig).
			// The ethereum hash is the SAME derived hash the tx is indexed under, so
			// callers can query it via eth_getTransactionByHash (HI-9); the sender and
			// composite key/signature let explorers recover/verify the real signer
			// without trusting the placeholder r/s/v (HI-8).
			let uxt = UncheckedExtrinsic::decode(&mut &extrinsic[..]).ok()?;
			match uxt.0.function {
				RuntimeCall::Ethereum(pallet_ethereum::Call::transact_blackchain {
					transaction,
				}) => {
					let eth_tx =
						pallet_ethereum::Pallet::<Runtime>::blackchain_to_evm_transaction(
							&transaction,
						)?;
					let eth_hash = eth_tx.hash();
					let sender = H160::from_slice(
						&sp_core::keccak_256(&transaction.pub_key)[12..],
					);
					Some((eth_hash, sender, transaction.pub_key, transaction.pqc_signature))
				}
				_ => None,
			}
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{baseline, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;

			use baseline::Pallet as BaselineBench;
			use frame_system_benchmarking::Pallet as SystemBench;

			use pallet_evm_precompile_curve25519_benchmarking::Pallet as EVMPrecompileCurve25519Bench;
			use pallet_evm_precompile_sha3fips_benchmarking::Pallet as EVMPrecompileSha3FIPSBench;

			let mut list = Vec::<BenchmarkList>::new();
			list_benchmarks!(list, extra);

			let storage_info = AllPalletsWithSystem::storage_info();
			(list, storage_info)
		}

		#[allow(non_local_definitions)]
		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> {
			use frame_benchmarking::{baseline, BenchmarkBatch};
			use frame_support::traits::TrackedStorageKey;

			use baseline::Pallet as BaselineBench;
			use frame_system_benchmarking::Pallet as SystemBench;
			use pallet_evm_precompile_curve25519_benchmarking::Pallet as EVMPrecompileCurve25519Bench;
			use pallet_evm_precompile_sha3fips_benchmarking::Pallet as EVMPrecompileSha3FIPSBench;

			impl baseline::Config for Runtime {}
			impl frame_system_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_curve25519_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_sha3fips_benchmarking::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = Vec::new();

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);
			add_benchmarks!(params, batches);
			Ok(batches)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{Runtime, WeightPerGas};
	#[test]
	fn configured_base_extrinsic_weight_is_evm_compatible() {
		let min_ethereum_transaction_weight = WeightPerGas::get() * 21_000;
		let base_extrinsic = <Runtime as frame_system::Config>::BlockWeights::get()
			.get(frame_support::dispatch::DispatchClass::Normal)
			.base_extrinsic;
		assert!(base_extrinsic.ref_time() <= min_ethereum_transaction_weight.ref_time());
	}
}

/// End-to-end proof of the PQC signed-extrinsic path: a `Balances::transfer`
/// submitted as a *standard signed Substrate extrinsic*, authenticated by a
/// composite PQC signature, is accepted by the runtime's own `Checkable::check`
/// (which re-derives the exact signed payload the signer committed to) — and a
/// tampered signature is rejected. This proves the signer and the runtime agree
/// on the payload bytes, closing the gap the `fp-account` unit tests don't cover.
#[cfg(test)]
mod pqc_signed_extrinsic_tests {
	use super::*;
	use blackchain_crypto_lib_rust::{sign_message, BlackChainPrivateKey};
	use fp_account::{AccountId20, PqcSignature, EXTRINSIC_DOMAIN_TAG};
	use scale_codec::Encode;
	use sp_core::hashing::keccak_256;
	use sp_runtime::{generic::Era, traits::Checkable, BuildStorage};

	fn key(seed: u8) -> BlackChainPrivateKey {
		BlackChainPrivateKey::generate(&[seed; 64]).expect("keygen").0
	}
	fn address(k: &BlackChainPrivateKey) -> AccountId20 {
		AccountId20(keccak_256(&k.public_key().to_bytes())[12..].try_into().unwrap())
	}

	fn signed_extra(nonce: u32) -> SignedExtra {
		cumulus_pallet_weight_reclaim::StorageWeightReclaim::new((
			frame_system::CheckNonZeroSender::new(),
			frame_system::CheckSpecVersion::new(),
			frame_system::CheckTxVersion::new(),
			frame_system::CheckGenesis::new(),
			frame_system::CheckEra::from(Era::Immortal),
			frame_system::CheckNonce::from(nonce),
			frame_system::CheckWeight::new(),
			pallet_transaction_payment::ChargeTransactionPayment::from(0),
			pqc_verify_weight::ChargePqcVerify::new(),
		))
	}

	fn new_test_ext(fund: &[(AccountId20, Balance)]) -> sp_io::TestExternalities {
		let mut t = frame_system::GenesisConfig::<Runtime>::default()
			.build_storage()
			.unwrap();
		pallet_balances::GenesisConfig::<Runtime> {
			balances: fund.to_vec(),
			..Default::default()
		}
		.assimilate_storage(&mut t)
		.unwrap();
		t.into()
	}

	/// Build a PQC-signed `UncheckedExtrinsic` for a transfer; `tamper` flips a
	/// signature byte to exercise the rejection path.
	fn signed_transfer(
		k: &BlackChainPrivateKey,
		dest: AccountId20,
		value: Balance,
		nonce: u32,
		tamper: bool,
	) -> UncheckedExtrinsic {
		let call = RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
			dest,
			value,
		});
		let extra = signed_extra(nonce);
		let payload = SignedPayload::new(call.clone(), extra.clone()).expect("payload");
		// Sign exactly what the runtime feeds `verify`: the (possibly hashed) signed
		// payload, prefixed with the extrinsic domain tag.
		let signed_msg = payload.using_encoded(|p| {
			let mut m = EXTRINSIC_DOMAIN_TAG.to_vec();
			m.extend_from_slice(p);
			m
		});
		let mut signature = sign_message(&signed_msg, k).expect("sign");
		if tamper {
			signature[0] ^= 0xFF;
		}
		let pub_key = k.public_key().to_bytes();
		UncheckedExtrinsic::new_signed(call, address(k), PqcSignature::new(pub_key, signature), extra)
	}

	#[test]
	fn pqc_signed_balances_transfer_authenticates() {
		let k = key(1);
		let sender = address(&k);
		let dest = AccountId20([0x22u8; 20]);

		new_test_ext(&[(sender, 1_000_000_000_000u128)]).execute_with(|| {
			let xt = signed_transfer(&k, dest, 1_000, 0, false);
			// The runtime's own Checkable re-derives the payload and runs the PQC
			// verifier; a correct composite signature must authenticate.
			let checked = xt.check(&frame_system::ChainContext::<Runtime>::default());
			assert!(checked.is_ok(), "PQC-signed extrinsic must authenticate via the runtime");
		});
	}

	#[test]
	fn tampered_pqc_signed_extrinsic_is_rejected() {
		let k = key(2);
		let sender = address(&k);
		let dest = AccountId20([0x33u8; 20]);

		new_test_ext(&[(sender, 1_000_000_000_000u128)]).execute_with(|| {
			let xt = signed_transfer(&k, dest, 1_000, 0, true);
			let checked = xt.check(&frame_system::ChainContext::<Runtime>::default());
			assert!(checked.is_err(), "a tampered PQC signature must be rejected");
		});
	}

	/// Cross-check: the runtime's `client::signing_message` must produce byte-for-byte
	/// the same signing bytes as the browser wallet's JS builder
	/// (`Blackchain-Wallet-Extension/src/lib/crypto/pqc-signed-extrinsic.js`), so the
	/// wallet and the chain agree on exactly what is signed. The expected hex below
	/// was emitted by that JS builder for these fixed inputs.
	#[test]
	fn signing_message_matches_wallet_js_builder() {
		let dest = AccountId20([0x44u8; 20]);
		let value: Balance = 1_000_000_000_000_000_000;
		let call = super::client::balances_transfer_call(dest, value);
		let genesis = sp_core::H256([0xabu8; 32]);
		let (_extra, msg) = super::client::signing_message(&call, 0, 0, 2, 1, genesis);
		let expected = "424c41434b434841494e5f45585452494e5349435f56310400444444444444444444444444444444444444444413000064a7b3b6e00d0000000200000001000000abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab";
		assert_eq!(hex::encode(&msg), expected, "runtime signing bytes must match the wallet JS builder");
	}

	/// The `client` helper (which supplies implicit values manually via `from_raw`,
	/// as an off-chain client must) produces an extrinsic the runtime authenticates
	/// — proving the client's manually-built implicit matches the chain's.
	#[test]
	fn client_helper_builds_authenticating_extrinsic() {
		let k = key(5);
		let sender = address(&k);
		let dest = AccountId20([0x55u8; 20]);

		new_test_ext(&[(sender, 1_000_000_000_000u128)]).execute_with(|| {
			let call = super::client::balances_transfer_call(dest, 1234);
			let spec = super::VERSION.spec_version;
			let txv = super::VERSION.transaction_version;
			let genesis = frame_system::BlockHash::<Runtime>::get::<u32>(0);
			let (extra, msg) = super::client::signing_message(&call, 0, 0, spec, txv, genesis);
			let signature = sign_message(&msg, &k).expect("sign");
			let xt = super::client::assemble(call, sender, k.public_key().to_bytes(), signature, extra);
			assert!(
				xt.check(&frame_system::ChainContext::<Runtime>::default()).is_ok(),
				"client-built PQC extrinsic must authenticate via the runtime",
			);
		});
	}

	/// CR-2 pre-filter: an unfunded claimed sender is rejected at
	/// `validate_transaction` with `Payment` — i.e. BEFORE the ~1.6 ms verify. (A
	/// correctly-signed extrinsic is used, so a `Payment` error proves the cheap
	/// balance pre-check ran first; the signature was never checked.)
	#[test]
	fn unfunded_signed_extrinsic_rejected_before_verify() {
		use sp_runtime::transaction_validity::InvalidTransaction;
		let unfunded = key(9); // deliberately NOT funded in genesis
		let funded = key(10);
		let dest = AccountId20([0x44u8; 20]);

		new_test_ext(&[(address(&funded), 1_000_000u128)]).execute_with(|| {
			// Unfunded claimed sender → dropped by the pre-filter with `Payment`
			// (a correctly-signed xt, so this proves the cheap check ran BEFORE the
			// signature verify).
			let xt = signed_transfer(&unfunded, dest, 1, 0, false);
			assert_eq!(
				super::pqc_signed_prefilter(&xt),
				Err(TransactionValidityError::Invalid(InvalidTransaction::Payment)),
				"unfunded claimed sender must be dropped before the PQC verify",
			);

			// A funded sender passes the pre-filter (then the normal pipeline runs).
			let ok = signed_transfer(&funded, dest, 1, 0, false);
			assert!(super::pqc_signed_prefilter(&ok).is_ok(), "funded sender passes the pre-filter");
		});
	}
}
