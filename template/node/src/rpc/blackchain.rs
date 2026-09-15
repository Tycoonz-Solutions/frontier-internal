//! Custom `blackchain_*` RPC namespace exposing BlackChain PQC transaction data
//! that the standard Ethereum JSON-RPC cannot represent (audit HI-8 / HI-9).
//!
//! A PQC transaction is presented to the Ethereum RPC as a wrapped EIP-1559 tx whose
//! `r`/`s`/`v` are non-cryptographic placeholders derived from `keccak256(pqc_sig)`.
//! Consequently the ethereum hash the tx is indexed under is not returned by
//! `author_submitExtrinsic` (HI-9), and the real composite public key + signature
//! (and thus an independently-recoverable sender) appear on no standard field (HI-8).
//! This namespace fills both gaps.

use std::{marker::PhantomData, sync::Arc};

use jsonrpsee::{
	core::{async_trait, RpcResult},
	proc_macros::rpc,
};
use scale_codec::{Decode, Encode};
use sc_client_api::BlockBackend;
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::{Bytes, H160, H256};
use sp_runtime::traits::Block as BlockT;

use fc_rpc::internal_err;
use fp_blackchain_rpc::BlackChainApi as BlackChainRuntimeApi;

/// Upper bound on a raw `blackchain_sendTransaction` payload. A well-formed
/// `transact_blackchain` extrinsic is ~7.6 KB fixed (2782 B pub_key + 4873 B sig)
/// plus EVM calldata; 1 MiB is far above any legitimate tx yet rejects multi-MB
/// junk BEFORE the runtime API + keccak run on it (public-endpoint amplification).
const MAX_RAW_TX_BYTES: usize = 1024 * 1024;

/// Hard cap on how many extrinsics `blackchain_getTransactionByHash` will hand to
/// the (WASM) runtime API in one call. Block limits already bound this, but the cap
/// makes the per-request work explicitly finite on a public read endpoint.
const MAX_BODY_SCAN: usize = 4096;

/// PQC transaction data returned by `blackchain_getTransactionByHash`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlackchainTxInfo {
	/// Ethereum hash the tx is indexed under (queryable via `eth_getTransactionByHash`).
	pub eth_hash: H256,
	/// The true PQC sender, `keccak256(pub_key)[12..]`.
	pub from: H160,
	/// 2782-byte composite public key (Dilithium5 ‖ P-521 ‖ Ed448).
	pub pub_key: Bytes,
	/// 4873-byte composite signature.
	pub pqc_signature: Bytes,
	/// Always `true`: the EIP-1559 `r`/`s`/`v` this tx exposes over the Ethereum RPC
	/// are non-cryptographic placeholders derived from `keccak256(pqc_signature)`.
	/// Do NOT `ecrecover(r,s,v)` — use `from` / `pub_key` / `pqc_signature` instead.
	pub placeholder_signature: bool,
}

#[rpc(server)]
pub trait BlackchainApi {
	/// Submit a bare `transact_blackchain` extrinsic and return the ETHEREUM tx hash
	/// (the hash it is indexed under), so a submitter can immediately query it via
	/// `eth_getTransactionByHash` — solving the submit-hash mismatch (HI-9).
	#[method(name = "blackchain_sendTransaction")]
	async fn send_transaction(&self, raw: Bytes) -> RpcResult<H256>;

	/// Look up a mined BlackChain tx by its ethereum hash and return its real PQC
	/// sender, composite public key and composite signature (HI-8). Returns `null`
	/// if the hash is unknown or is not a BlackChain PQC transaction.
	#[method(name = "blackchain_getTransactionByHash")]
	async fn get_transaction_by_hash(&self, hash: H256) -> RpcResult<Option<BlackchainTxInfo>>;
}

/// Implementation of the `blackchain_*` RPC namespace.
pub struct Blackchain<B: BlockT, C, P> {
	client: Arc<C>,
	pool: Arc<P>,
	frontier_backend: Arc<dyn fc_api::Backend<B>>,
	_marker: PhantomData<B>,
}

impl<B: BlockT, C, P> Blackchain<B, C, P> {
	pub fn new(
		client: Arc<C>,
		pool: Arc<P>,
		frontier_backend: Arc<dyn fc_api::Backend<B>>,
	) -> Self {
		Self {
			client,
			pool,
			frontier_backend,
			_marker: PhantomData,
		}
	}
}

#[async_trait]
impl<B, C, P> BlackchainApiServer for Blackchain<B, C, P>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + BlockBackend<B> + Send + Sync + 'static,
	C::Api: BlackChainRuntimeApi<B>,
	P: TransactionPool<Block = B> + 'static,
	B::Extrinsic: Encode + Decode,
{
	async fn send_transaction(&self, raw: Bytes) -> RpcResult<H256> {
		let bytes = raw.0;
		if bytes.is_empty() {
			return Err(internal_err("transaction data is empty"));
		}
		// Reject oversized payloads up front, before the decode + runtime API + keccak
		// run on attacker-controlled bytes (public-endpoint amplification defence).
		if bytes.len() > MAX_RAW_TX_BYTES {
			return Err(internal_err(format!(
				"transaction data too large: {} bytes (max {MAX_RAW_TX_BYTES})",
				bytes.len()
			)));
		}
		let xt = B::Extrinsic::decode(&mut &bytes[..])
			.map_err(|e| internal_err(format!("failed to decode extrinsic: {e:?}")))?;

		let best = self.client.info().best_hash;
		let info = self
			.client
			.runtime_api()
			.blackchain_tx_info(best, bytes)
			.map_err(|e| internal_err(format!("runtime api error: {e:?}")))?;
		let (eth_hash, _sender, _pk, _sig) =
			info.ok_or_else(|| internal_err("not a transact_blackchain extrinsic"))?;

		// External: a public RPC submission is NOT operator-originated. `Local` would
		// mark it node-trusted (bypasses reputation/propagation limits) — inappropriate
		// for arbitrary callers. Signature/economic validation is unaffected either way.
		self.pool
			.submit_one(best, TransactionSource::External, xt)
			.await
			.map_err(|e| internal_err(format!("pool rejected extrinsic: {e:?}")))?;

		Ok(eth_hash)
	}

	async fn get_transaction_by_hash(
		&self,
		hash: H256,
	) -> RpcResult<Option<BlackchainTxInfo>> {
		let metadata = self
			.frontier_backend
			.transaction_metadata(&hash)
			.await
			.map_err(|e| internal_err(format!("frontier backend error: {e}")))?;
		let Some(meta) = metadata.into_iter().next() else {
			return Ok(None);
		};
		let sub_hash = meta.substrate_block_hash;

		let Some(exts) = self
			.client
			.block_body(sub_hash)
			.map_err(|e| internal_err(format!("block body error: {e:?}")))?
		else {
			return Ok(None);
		};

		let api = self.client.runtime_api();
		// Bounded scan: `metadata` already pins the hash to this block; we walk its
		// extrinsics to recover the composite pub_key/sig for the matching one. The cap
		// keeps per-request runtime-API work finite on a public read endpoint.
		for ext in exts.into_iter().take(MAX_BODY_SCAN) {
			let ext_bytes = ext.encode();
			if let Some((eth_hash, from, pub_key, pqc_signature)) = api
				.blackchain_tx_info(sub_hash, ext_bytes)
				.map_err(|e| internal_err(format!("runtime api error: {e:?}")))?
			{
				if eth_hash == hash {
					return Ok(Some(BlackchainTxInfo {
						eth_hash,
						from,
						pub_key: pub_key.into(),
						pqc_signature: pqc_signature.into(),
						placeholder_signature: true,
					}));
				}
			}
		}
		Ok(None)
	}
}
