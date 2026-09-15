// This file is part of Frontier / BlackChain.
// SPDX-License-Identifier: Apache-2.0

//! # Weights for `pallet-ethereum` BlackChain PQC calls
//!
//! ## Source of truth
//!
//! These weights come from `frame-benchmarking` (`benchmark pallet`), NOT a raw crypto
//! micro-benchmark. The benchmark verifies a REAL signed composite Dilithium5 + P-521 +
//! Ed448 transaction through the full production path — SCALE decode + reconstruct +
//! `verify_pqc_transaction` host function — so the measurement includes the host-function
//! boundary and decode overhead, not just the crypto.
//!
//! Measured on Apple Silicon (release build, `--steps=50 --repeat=20`), against the
//! 2026-08-05 FIPS 204 ML-DSA-87 crypto library (`ml-dsa 0.1.1`, fixed-width low-S
//! P-521, exact-length 4873-byte composite):
//!
//! | Metric              | Value            |
//! |---------------------|------------------|
//! | Extrinsic Time      | ~2,568 µs        |
//! | Reads               | 0                |
//! | Writes              | 0                |
//! | Recorded proof size | 0                |
//!
//! History: crystals-Dilithium5 measured ~1,641 µs on the same path/hardware; the
//! FIPS 204 ML-DSA-87 migration (pure-Rust `ml-dsa` crate) raised verification to
//! ~2,568 µs (≈1.56×). Pre-hardening (DER P-521) measured ~3,577 µs. The benchmark
//! verifies a REAL signed vector (sanity-asserted), so this is the full-completion cost.
//!
//! ## ⚠️ Before production
//!
//! This is a DEV-HARDWARE measurement. Re-run on target validator hardware:
//! ```bash
//! cargo build --release --features runtime-benchmarks -p frontier-template-node
//! ./target/release/frontier-template-node benchmark pallet \
//!     --chain=dev --pallet=pallet_ethereum --extrinsic=pqc_verify_signature \
//!     --steps=20 --repeat=10 --no-storage-info
//! ```
//! Then update `PQC_VERIFY_MICROS` below. The benchmark embeds a valid signed vector
//! (`pqc_benchmark_vector.bin`); regenerate it with `pqc-tx-test --gen-vector` if the
//! transaction format changes.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens, unused_imports, missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Full-path composite PQC verification (Dil5 + P-521 + Ed448) including the host-function
/// boundary + SCALE decode, measured via `frame-benchmarking` on Apple Silicon.
/// Unit: microseconds.
const PQC_VERIFY_MICROS: u64 = 2_568;

/// Total ref_time weight in picoseconds (Substrate ref_time: 1e12 units = 1 s, so 1 µs = 1e6).
const PQC_VERIFY_REF_TIME_PS: u64 = PQC_VERIFY_MICROS * 1_000_000;

/// Weight functions needed by `pallet-ethereum` for BlackChain PQC operations.
pub trait BlackChainWeightInfo {
	/// Weight of verifying one composite PQC signature (Dilithium5 + P-521 + Ed448).
	fn pqc_verify_signature() -> Weight;
}

/// Weights derived from the `blackchain-crypto-lib-rust` Criterion benchmark.
///
/// # Security Note
/// `pqc_verify_signature` is called once per `transact_blackchain` extrinsic.
/// Under-charging would allow an attacker to DDoS validators cheaply; these
/// weights ensure PQC transactions are priced proportional to their actual cost.
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> BlackChainWeightInfo for SubstrateWeight<T> {
	fn pqc_verify_signature() -> Weight {
		// Proof Size: 0 (no trie reads — pure computation).
		// ref_time: measured ~2.57 ms (ML-DSA-87 + P-521 + Ed448 via host fn, incl. bridge).
		Weight::from_parts(PQC_VERIFY_REF_TIME_PS, 0u64)
	}
}

/// Fallback for tests and environments without benchmarked weights.
impl BlackChainWeightInfo for () {
	fn pqc_verify_signature() -> Weight {
		Weight::from_parts(PQC_VERIFY_REF_TIME_PS, 0u64)
	}
}
