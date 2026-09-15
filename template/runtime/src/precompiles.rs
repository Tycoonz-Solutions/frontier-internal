use core::marker::PhantomData;
use pallet_evm::{
	IsPrecompileResult, Precompile, PrecompileHandle, PrecompileResult, PrecompileSet,
};
use sp_core::H160;

use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_simple::{
	BlackChainMessageVerify, BlackChainVerify, Identity, Ripemd160, Sha256,
};

pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	pub fn new() -> Self {
		Self(Default::default())
	}
	pub fn used_addresses() -> [H160; 7] {
		[
			hash(1),
			hash(2),
			hash(3),
			hash(4),
			hash(5),
			hash(1024),
			hash(1028), // BlackChainMessageVerify (PQC personal_sign / arbitrary-message)
			// NOTE: classical-crypto precompiles removed for a PQC-only chain:
			//   1025 ECRecoverPublicKey (secp256k1 ECDSA),
			//   1026/1027 Curve25519 (classical elliptic-curve ops).
		]
	}
}
impl<R> PrecompileSet for FrontierPrecompiles<R>
where
	R: pallet_evm::Config + frame_system::Config,
{
	fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
		match handle.code_address() {
			// BlackChain post-quantum signature verification (replaces secp256k1 ecrecover) :
			a if a == hash(1) => Some(BlackChainVerify::execute(handle)),
			a if a == hash(2) => Some(Sha256::execute(handle)),
			a if a == hash(3) => Some(Ripemd160::execute(handle)),
			a if a == hash(4) => Some(Identity::execute(handle)),
			a if a == hash(5) => Some(Modexp::execute(handle)),
			// Non-Frontier specific nor Ethereum precompiles :
			a if a == hash(1024) => Some(Sha3FIPS256::<
				R,
				crate::weights::pallet_evm_precompile_sha3fips::WeightInfo<R>,
			>::execute(handle)),
			// BlackChain PQC arbitrary-message verification (personal_sign / signMessage):
			a if a == hash(1028) => Some(BlackChainMessageVerify::execute(handle)),
			// Classical-crypto precompiles removed for a PQC-only chain:
			//   1025 ECRecoverPublicKey (secp256k1 ECDSA)
			//   1026 Curve25519Add / 1027 Curve25519ScalarMul (classical ECC)
			_ => None,
		}
	}

	fn is_precompile(&self, address: H160, _gas: u64) -> IsPrecompileResult {
		IsPrecompileResult::Answer {
			is_precompile: Self::used_addresses().contains(&address),
			extra_cost: 0,
		}
	}
}

fn hash(a: u64) -> H160 {
	H160::from_low_u64_be(a)
}
