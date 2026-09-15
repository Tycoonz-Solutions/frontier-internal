// This file is part of Frontier / BlackChain.
// SPDX-License-Identifier: Apache-2.0

//! # BlackChain PQC benchmarks for `pallet-ethereum`
//!
//! Measures the wall-clock cost of verifying a composite Dilithium5 + P-521 + Ed448
//! signature so that `transact_blackchain` can be assigned accurate Substrate weights.
//!
//! ## How to run
//!
//! ```bash
//! # From the frontier workspace root:
//! cargo build --profile=production --features=runtime-benchmarks -p frontier-template-node
//!
//! ./target/production/frontier-template-node benchmark pallet \
//!     --chain=dev \
//!     --pallet=pallet_ethereum \
//!     --extrinsic="pqc_verify_signature" \
//!     --steps=50 \
//!     --repeat=20 \
//!     --output=frame/ethereum/src/weights.rs \
//!     --template=./.maintain/frame-weight-template.hbs
//! ```
//!
//! After running, replace the `PQC_VERIFY_OVERHEAD_REF_TIME` constant in `lib.rs` with
//! `<T as Config>::BlackChainWeightInfo::pqc_verify_signature()`.

#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite};

use super::*;
use crate::pallet::{Config, Pallet};

benchmarks! {
	pqc_verify_signature {
		// A REAL, VALID signed `BlackChainTransaction`, SCALE-encoded exactly as the
		// pallet passes it to the `verify_pqc_transaction` host function. Generated via:
		//   cargo run -p pqc-tx-test --bin pqc-tx-test -- --gen-vector \
		//       frame/ethereum/src/pqc_benchmark_vector.bin
		//
		// Using a VALID vector is essential: it forces the full Dilithium5 + P-521 +
		// Ed448 verification to run to completion (the true worst case). Dummy/zero
		// keys fail the very first key-parse and would under-measure the cost by orders
		// of magnitude, producing weights that dangerously under-charge the extrinsic.
		let encoded_tx: alloc::vec::Vec<u8> =
			include_bytes!("pqc_benchmark_vector.bin").to_vec();

		// Fail fast (outside the timed section) if the embedded vector ever stops
		// verifying — otherwise the benchmark would silently measure an early-exit path.
		let sanity =
			pallet_ethereum_blackchain_hf::blackchain_crypto::verify_pqc_transaction(encoded_tx.clone());
		assert_eq!(
			sanity.len(),
			20,
			"embedded benchmark vector must verify (full Dil5+P521+Ed448 path); regenerate with --gen-vector"
		);
	}: {
		// Timed section: mirrors the exact call path of transact_blackchain.
		let _ = pallet_ethereum_blackchain_hf::blackchain_crypto::verify_pqc_transaction(encoded_tx);
	}
	verify {
		// No post-condition: this is a pure timing benchmark.
	}
}

impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
