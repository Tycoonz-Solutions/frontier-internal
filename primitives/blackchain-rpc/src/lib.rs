// fp-blackchain-rpc — runtime API bridging BlackChain PQC transaction data to the
// node RPC layer (audit HI-8 / HI-9).
//
// A BlackChain PQC transaction is presented to the Ethereum RPC as a wrapped
// EIP-1559 transaction whose `r`/`s`/`v` are NON-CRYPTOGRAPHIC placeholders derived
// from `keccak256(pqc_signature)`. That means:
//   * the ethereum hash under which the tx becomes queryable is derived from those
//     placeholders, so a submitter needs it returned to them (HI-9), and
//   * the real composite public key + signature appear on no standard RPC field, so
//     an explorer/indexer cannot recover the true sender or verify the signature
//     (HI-8) — and must not `ecrecover(r,s,v)`, which yields garbage.
//
// This runtime API decodes a bare `transact_blackchain` extrinsic and returns the
// ethereum hash plus the real sender / composite public key / composite signature,
// which the `blackchain_*` RPC namespace exposes.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

use sp_core::{H160, H256};

sp_api::decl_runtime_apis! {
	/// Runtime API for BlackChain PQC transaction introspection.
	pub trait BlackChainApi {
		/// Given the SCALE bytes of a single (bare) extrinsic, return, if it is a
		/// `transact_blackchain` call:
		///   `(ethereum_tx_hash, sender, composite_public_key, composite_signature)`
		///
		/// * `ethereum_tx_hash` — the hash the transaction is indexed under and can
		///   be queried with via `eth_getTransactionByHash` (HI-9).
		/// * `sender` — `keccak256(public_key)[12..]`, the true PQC sender (HI-8).
		/// * `composite_public_key` — 2782-byte Dilithium5‖P-521‖Ed448 public key.
		/// * `composite_signature` — 4873-byte composite signature.
		///
		/// Returns `None` for any other call (including classic `transact`).
		fn blackchain_tx_info(extrinsic: Vec<u8>) -> Option<(H256, H160, Vec<u8>, Vec<u8>)>;
	}
}
