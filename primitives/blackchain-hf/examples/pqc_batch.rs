//! `pqc_batch` — build and verify **batches** of BlackChain PQC transactions
//! against the real batch verifier.
//!
//! It drives `pallet_ethereum_blackchain_hf::verify_batch_core` — the exact
//! native body of the `verify_pqc_transaction_batch` host function the runtime
//! calls — so what you verify here is identical to what a node verifies, with
//! no node, RPC or externalities needed.
//!
//! Run with `--release` (the full ML-DSA-87 + P-521 + Ed448 verify is ~100x
//! slower in debug):
//!
//! ```text
//! # 1. Create a batch of 8 txs; tamper #2 and #5 so they MUST be rejected.
//! cargo run -p pallet-ethereum-blackchain-hf --release --example pqc_batch -- \
//!     create --count 8 --tamper 2,5 --out batch.hex
//!
//! # 2. Send the batch file to the verifier: prints per-tx OK/REJECTED + timing.
//! cargo run -p pallet-ethereum-blackchain-hf --release --example pqc_batch -- \
//!     verify --in batch.hex
//!
//! # One-shot (create in memory + verify immediately):
//! cargo run -p pallet-ethereum-blackchain-hf --release --example pqc_batch -- \
//!     demo --count 16 --tamper 3,9
//! ```
//!
//! The batch file is just the hex of the SCALE-encoded `Vec<Vec<u8>>` envelope
//! (one inner `Vec<u8>` per encoded `BlackChainTransaction`). You can hand-edit
//! it to corrupt bytes yourself and re-run `verify` to watch it get rejected.

use std::time::Instant;

use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{create_wallet, sign_transaction, BlackChainTxType};
use fp_blackchain_crypto::BlackChainTransaction;
use pallet_ethereum_blackchain_hf::{verify_batch_core, verify_one_tx};
use scale_codec::{Decode, Encode};

/// Chain id bound into every signature (any value works as long as create and
/// verify agree — the signing hash and entanglement nonce both depend on it).
const CHAIN_ID: u64 = 42;

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");

	match cmd {
		"create" => cmd_create(&args[2..]),
		"verify" => cmd_verify(&args[2..]),
		"demo" => cmd_demo(&args[2..]),
		"cores" => cmd_cores(&args[2..]),
		_ => {
			eprintln!(
				"pqc_batch — create and verify batches of PQC transactions\n\n\
				 USAGE:\n  \
				 create --count N [--tamper i,j,...] [--chain-id C] [--out FILE]\n  \
				 verify --in FILE [--cores]\n  \
				 demo   [--count N] [--tamper i,j,...] [--cores]\n  \
				 cores  [--count N] [--repeat K]   # per-core work distribution only\n\n\
				 (--cores adds a per-core work histogram after the verdicts.)\n\
				 Run with --release. Batch file = hex of SCALE Vec<Vec<u8>> envelope.\n\
				 Limit workers with RAYON_NUM_THREADS=N."
			);
			std::process::exit(2);
		}
	}
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn cmd_create(args: &[String]) {
	let count: usize = flag(args, "--count").and_then(|s| s.parse().ok()).unwrap_or(8);
	let chain_id: u64 = flag(args, "--chain-id").and_then(|s| s.parse().ok()).unwrap_or(CHAIN_ID);
	let out = flag(args, "--out").unwrap_or_else(|| "batch.hex".to_string());
	let tamper = parse_indices(flag(args, "--tamper"));

	let (envelope, items, signers) = build_batch(count, chain_id, &tamper);

	std::fs::write(&out, format!("0x{}\n", hex::encode(&envelope)))
		.unwrap_or_else(|e| panic!("failed to write {out}: {e}"));

	println!("created batch of {count} tx (chain_id {chain_id}) -> {out}");
	println!("  envelope: {} bytes ({} hex chars)", envelope.len(), envelope.len() * 2);
	println!("  {:>3}  {:>8}  {:<42}  expected", "idx", "bytes", "signer");
	for i in 0..count {
		let mark = if tamper.contains(&i) { "TAMPERED -> must be REJECTED" } else { "valid -> must be ACCEPTED" };
		println!(
			"  {:>3}  {:>8}  0x{}  {mark}",
			i,
			items[i].len(),
			hex::encode(signers[i]),
		);
	}
	println!("\nnow verify it:\n  cargo run -p pallet-ethereum-blackchain-hf --release --example pqc_batch -- verify --in {out}");
}

fn cmd_verify(args: &[String]) {
	let path = flag(args, "--in").unwrap_or_else(|| {
		eprintln!("verify: --in FILE is required");
		std::process::exit(2);
	});
	let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
	let cleaned: String = raw.split_whitespace().collect();
	let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
	let envelope = hex::decode(cleaned).unwrap_or_else(|e| panic!("{path} is not valid hex: {e}"));

	let want_cores = has_flag(args, "--cores");

	// Decode the envelope into its items (kept for the optional per-core report).
	let items = match Vec::<Vec<u8>>::decode(&mut &envelope[..]) {
		Ok(items) => items,
		Err(e) => {
			println!("envelope FAILED to decode as Vec<Vec<u8>>: {e:?}");
			println!("verify_batch_core returned {} bytes (expected empty on bad envelope)", verify_batch_core(&envelope).len());
			std::process::exit(1);
		}
	};
	let n = items.len();

	println!("verifying {n} tx from {path} ({} byte envelope) on {} core(s)\n", envelope.len(), rayon::current_num_threads());

	let t0 = Instant::now();
	let out = verify_batch_core(&envelope);
	let elapsed = t0.elapsed();

	report(&out, n, elapsed);

	if want_cores {
		println!();
		print_core_distribution(&items, 1);
	}
}

fn cmd_demo(args: &[String]) {
	let count: usize = flag(args, "--count").and_then(|s| s.parse().ok()).unwrap_or(16);
	let tamper = parse_indices(flag(args, "--tamper"));
	let want_cores = has_flag(args, "--cores");
	let (envelope, items, _signers) = build_batch(count, CHAIN_ID, &tamper);

	println!("demo: {count} tx ({} tampered) on {} core(s)\n", tamper.len(), rayon::current_num_threads());
	let t0 = Instant::now();
	let out = verify_batch_core(&envelope);
	let elapsed = t0.elapsed();
	report(&out, count, elapsed);

	if want_cores {
		println!();
		print_core_distribution(&items, 1);
	}
}

/// Report how the parallel verification work is distributed across CPU cores.
///
/// Builds a batch (clones of one signed tx — the distribution doesn't depend on
/// the signer) and reports the per-core split. `--repeat K` runs K rounds to
/// produce a sustained load you can also watch in a system monitor.
/// Limit the worker count with the `RAYON_NUM_THREADS` env var.
fn cmd_cores(args: &[String]) {
	let cores = rayon::current_num_threads();
	let count: usize = flag(args, "--count").and_then(|s| s.parse().ok()).unwrap_or(cores * 64);
	let repeat: usize = flag(args, "--repeat").and_then(|s| s.parse().ok()).unwrap_or(1);

	println!("building {count} tx (cloned from one signed tx)...");
	let (base, _) = build_signed_item(0, CHAIN_ID);
	let items: Vec<Vec<u8>> = std::iter::repeat_with(|| base.clone()).take(count).collect();

	print_core_distribution(&items, repeat);
}

/// Shared per-core distribution report.
///
/// Mirrors `verify_batch_core`'s `par_iter`, but tags each item with the rayon
/// worker thread (`rayon::current_thread_index()`) that handled it, verifying
/// every item `repeat` times and printing a per-core histogram. Tampered items
/// are allowed (they just verify as failures) — this reports *where* the work
/// ran, not whether each tx was valid.
fn print_core_distribution(items: &[Vec<u8>], repeat: usize) {
	use rayon::prelude::*;
	use std::sync::Mutex;

	let cores = rayon::current_num_threads();
	let counts: Vec<Mutex<usize>> = (0..cores).map(|_| Mutex::new(0)).collect();

	println!("core distribution: {} tx x {repeat} round(s) across {cores} worker(s)\n", items.len());
	let t0 = Instant::now();
	for _ in 0..repeat {
		items.par_iter().for_each(|enc| {
			if let Some(idx) = rayon::current_thread_index() {
				if idx < cores {
					*counts[idx].lock().unwrap() += 1;
				}
			}
			let _ = verify_one_tx(enc);
		});
	}
	let elapsed = t0.elapsed();

	let per_core: Vec<usize> = counts.iter().map(|c| *c.lock().unwrap()).collect();
	let total: usize = per_core.iter().sum();
	let used = per_core.iter().filter(|&&c| c > 0).count();
	let mean = total as f64 / cores as f64;
	let maxc = *per_core.iter().max().unwrap_or(&0);
	let minc = *per_core.iter().min().unwrap_or(&0);

	println!("per-core work (items handled):");
	let scale = maxc.max(1) as f64;
	for (i, c) in per_core.iter().enumerate() {
		let bar = "#".repeat(((*c as f64 / scale) * 40.0).round() as usize);
		println!("  core {i:2}: {c:7}  {bar}");
	}

	let imbalance = if mean > 0.0 { (maxc as f64 - minc as f64) / mean * 100.0 } else { 0.0 };
	println!(
		"\n{used}/{cores} cores used | total {total} | mean {mean:.0}/core | min {minc} | max {maxc} | imbalance {imbalance:.0}% of mean",
	);
	println!(
		"wall {elapsed:?} | {:.0} verifications/sec",
		total as f64 / elapsed.as_secs_f64(),
	);
	if total < cores * 8 {
		println!(
			"note: only {total} verifications across {cores} cores — too few to judge balance.\n\
			 For a representative distribution use e.g. `cores --count {}` (or a larger batch).",
			cores * 64,
		);
	} else if used == cores {
		println!("=> work IS spread across all {cores} cores");
	} else {
		println!("=> only {used} of {cores} cores were used");
	}
}

// ---------------------------------------------------------------------------
// Core helpers
// ---------------------------------------------------------------------------

/// Build `count` freshly-signed transactions (distinct keypair + nonce each),
/// flipping a byte in every index listed in `tamper`. Returns the SCALE
/// `Vec<Vec<u8>>` envelope, the individual encoded items, and the expected
/// signer per index (zero for tampered items).
fn build_batch(count: usize, chain_id: u64, tamper: &[usize]) -> (Vec<u8>, Vec<Vec<u8>>, Vec<[u8; 20]>) {
	let mut items = Vec::with_capacity(count);
	let mut signers = Vec::with_capacity(count);

	for i in 0..count {
		let (mut encoded, signer) = build_signed_item(i as u64, chain_id);
		if tamper.contains(&i) {
			// Flip a byte in the public-key tail: the signature no longer
			// matches the address it recovers, so verification must fail.
			let last = encoded.len() - 1;
			encoded[last] ^= 0xFF;
			signers.push([0u8; 20]);
		} else {
			signers.push(signer);
		}
		items.push(encoded);
	}

	let envelope = items.encode();
	(envelope, items, signers)
}

/// Sign one transaction and return its on-chain SCALE bytes + recovered signer.
fn build_signed_item(nonce: u64, chain_id: u64) -> (Vec<u8>, [u8; 20]) {
	let (_mnemonic, key) = create_wallet("").expect("create_wallet failed");

	let mut tx = BlackChainTxType {
		chain_id,
		nonce,
		max_priority_fee_per_gas: U256::from(1_000_000_000u64),
		max_fee_per_gas: U256::from(10_000_000_000u64),
		gas_limit: 21_000,
		to: Some(Address::ZERO),
		value: U256::ZERO,
		data: Bytes::default(),
		v: None,
		r: None,
		s: None,
		pqc_signature: None,
		pub_key: None,
	};
	sign_transaction(&mut tx, &key).expect("signing failed");

	let on_chain = BlackChainTransaction {
		chain_id: tx.chain_id,
		nonce: tx.nonce,
		max_priority_fee_per_gas: tx.max_priority_fee_per_gas.to_be_bytes::<32>(),
		max_fee_per_gas: tx.max_fee_per_gas.to_be_bytes::<32>(),
		gas_limit: tx.gas_limit,
		to: tx.to.map(|a| a.into_array()).unwrap_or([0u8; 20]),
		is_create: tx.to.is_none(),
		value: tx.value.to_be_bytes::<32>(),
		input: tx.data.to_vec(),
		v: tx.v.map(|v| v.to::<u64>()).unwrap_or(tx.chain_id * 2 + 35),
		r: [0u8; 32],
		s: [0u8; 32],
		pqc_signature: tx.pqc_signature.expect("signed tx has signature").to_vec(),
		pub_key: tx.pub_key.expect("signed tx has pubkey").to_vec(),
	};

	let encoded = on_chain.encode();
	let out = verify_one_tx(&encoded);
	let mut signer = [0u8; 20];
	if out.len() == 20 {
		signer.copy_from_slice(&out);
	}
	(encoded, signer)
}

/// Print the per-index verdict table from a `20*N` result buffer.
fn report(out: &[u8], n: usize, elapsed: std::time::Duration) {
	if out.len() != n * 20 {
		println!("UNEXPECTED: result is {} bytes, expected {} (20 x {n})", out.len(), n * 20);
	}

	let mut accepted = 0usize;
	let mut rejected = 0usize;
	println!("  {:>3}  {:<10}  signer", "idx", "status");
	for i in 0..n {
		let chunk = &out[i * 20..i * 20 + 20];
		if chunk == [0u8; 20] {
			rejected += 1;
			println!("  {:>3}  {:<10}  —", i, "REJECTED");
		} else {
			accepted += 1;
			println!("  {:>3}  {:<10}  0x{}", i, "OK", hex::encode(chunk));
		}
	}

	let per_tx = if n > 0 { elapsed.as_secs_f64() * 1000.0 / n as f64 } else { 0.0 };
	println!(
		"\n{n} tx: {accepted} accepted, {rejected} rejected  |  {:?} total, {per_tx:.2} ms/tx avg across {} core(s)",
		elapsed,
		rayon::current_num_threads(),
	);
}

// ---------------------------------------------------------------------------
// Tiny arg parsing (no external deps)
// ---------------------------------------------------------------------------

/// Value following `--name`, if present.
fn flag(args: &[String], name: &str) -> Option<String> {
	args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

/// Whether a bare `--name` flag is present.
fn has_flag(args: &[String], name: &str) -> bool {
	args.iter().any(|a| a == name)
}

/// Parse a comma-separated index list like "2,5,9".
fn parse_indices(v: Option<String>) -> Vec<usize> {
	v.map(|s| s.split(',').filter_map(|p| p.trim().parse().ok()).collect())
		.unwrap_or_default()
}
