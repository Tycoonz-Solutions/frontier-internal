// pqc_prewarm — block-import cache pre-pass.
//
// Wraps the block-import pipeline so that, right BEFORE a block is executed, the
// node verifies all of that block's PQC signatures in ONE parallel pass and warms
// the native verify cache (`pallet_ethereum_blackchain_hf::verify_mixed_batch_core`).
// When the runtime then executes the block, each signature check — whether a
// self-contained EVM `transact_blackchain` call or the `PqcSignature::verify` of a
// signed Substrate extrinsic — is a cache hit instead of a fresh ~1.6 ms verify.
//
// Two paths are warmed:
//   * EVM:    self-contained `0x05 ‖ 7 ‖ 1 ‖ SCALE(BlackChainTransaction)`
//             → `PqcBatchItem::Transaction(args)`.
//   * Signed: any PQC-signed extrinsic `0x84 ‖ from(20) ‖ PqcSignature ‖ extra ‖ call`
//             → `PqcBatchItem::Message { message, signature, pub_key }`, where
//             `message = EXTRINSIC_DOMAIN_TAG ‖ (call ‖ extra ‖ implicit)` — exactly
//             what `PqcSignature::verify` reconstructs and hands the host function.
//             (Native BTT transfers are `Balances::transfer_allow_death` on this path.)
//
// This is PURELY a performance optimization and is best-effort: the cache only ever
// stores *successful* verifications of exact input bytes, so a parse mismatch, a
// mortal era we can't reconstruct, or an unavailable runtime version simply yields a
// cache miss and the runtime verifies the signature normally. It can never change a
// verification result or the resulting state — consensus is unaffected.

use std::marker::PhantomData;
use std::sync::Arc;

use sc_consensus::{BlockCheckParams, BlockImport, BlockImportParams, ImportResult};
use scale_codec::{Decode, Encode};
use sp_api::{Core, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT};

use fp_account::{COMPOSITE_PK_SIZE, COMPOSITE_SIG_SIZE, EXTRINSIC_DOMAIN_TAG};
use pallet_ethereum_blackchain_hf::{cache_stats, verify_mixed_batch_core, PqcBatchItem};

// construct_runtime index / call index for the template runtime's EVM path. If it
// ever drifts from the runtime, the pre-pass simply stops warming that call (the
// runtime still verifies it) — it is never a correctness issue.
const ETHEREUM_PALLET_INDEX: u8 = 7;
const TRANSACT_BLACKCHAIN_CALL: u8 = 1;

// Extrinsic preamble bytes: a self-contained (bare) call vs a signed extrinsic
// (`LEGACY_FORMAT_VERSION 4 | SIGNED bit 0x80`).
const SELF_CONTAINED_PREAMBLE: u8 = 0x05;
const SIGNED_PREAMBLE: u8 = 0x84;

/// Additional-signed (implicit) context needed to reconstruct a signed extrinsic's
/// signing payload: `specVersion ‖ txVersion ‖ genesis ‖ eraBlock`.
struct SignedCtx {
	spec_version: u32,
	tx_version: u32,
	genesis: [u8; 32],
}

/// Block-import wrapper that warms the PQC verify cache before the inner import
/// executes the block.
pub struct PqcPrewarmBlockImport<B: BlockT, I, C> {
	inner: I,
	client: Arc<C>,
	_marker: PhantomData<B>,
}

impl<B: BlockT, I: Clone, C> Clone for PqcPrewarmBlockImport<B, I, C> {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
			client: self.client.clone(),
			_marker: PhantomData,
		}
	}
}

impl<B: BlockT, I, C> PqcPrewarmBlockImport<B, I, C> {
	pub fn new(inner: I, client: Arc<C>) -> Self {
		Self {
			inner,
			client,
			_marker: PhantomData,
		}
	}
}

impl<B, I, C> PqcPrewarmBlockImport<B, I, C>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + HeaderBackend<B>,
	C::Api: Core<B>,
{
	/// Extract the block's PQC signatures and verify them in parallel to warm the cache.
	fn warm(&self, parent: B::Hash, body: &[B::Extrinsic]) {
		// Canonical bytes of each extrinsic: `preamble ‖ …` (one length prefix peeled).
		let blobs: Vec<Vec<u8>> = body.iter().map(canonical_bytes).collect();

		// The signed-extrinsic path needs the runtime version + genesis to rebuild the
		// signing payload. Fetch it once per block, and only if a signed extrinsic is
		// actually present (EVM-only / empty blocks pay nothing).
		let has_signed = blobs.iter().any(|b| b.first() == Some(&SIGNED_PREAMBLE));
		let ctx = if has_signed { self.signed_ctx(parent) } else { None };

		let items: Vec<PqcBatchItem> = blobs
			.iter()
			.filter_map(|b| extract_item(b, ctx.as_ref()))
			.collect();

		if !items.is_empty() {
			// Verify every signature in parallel; results populate the native cache.
			let _ = verify_mixed_batch_core(&items.encode());
			log::debug!(
				target: "pqc_prewarm",
				"pre-verified {} PQC signature(s) in parallel to warm the import cache",
				items.len(),
			);
		}
	}

	/// Runtime version (spec/tx) at the parent + the chain's genesis hash, or `None`
	/// if the runtime version can't be read (→ signed extrinsics simply aren't warmed).
	fn signed_ctx(&self, parent: B::Hash) -> Option<SignedCtx> {
		let version = self.client.runtime_api().version(parent).ok()?;
		let gb = self.client.info().genesis_hash;
		let gb = gb.as_ref();
		if gb.len() != 32 {
			return None;
		}
		let mut genesis = [0u8; 32];
		genesis.copy_from_slice(gb);
		Some(SignedCtx {
			spec_version: version.spec_version,
			tx_version: version.transaction_version,
			genesis,
		})
	}
}

/// Peel the single length prefix a block extrinsic (`OpaqueExtrinsic`) carries,
/// yielding the canonical bytes `preamble ‖ …`.
fn canonical_bytes<E: Encode>(ext: &E) -> Vec<u8> {
	let encoded = ext.encode();
	Decode::decode(&mut encoded.as_slice()).unwrap_or(encoded)
}

/// Turn one canonical extrinsic into a `PqcBatchItem`, or `None` if it is not a PQC
/// call we recognise (or we lack the context to reconstruct a signed one).
fn extract_item(blob: &[u8], ctx: Option<&SignedCtx>) -> Option<PqcBatchItem> {
	match *blob.first()? {
		SELF_CONTAINED_PREAMBLE => extract_evm(blob),
		SIGNED_PREAMBLE => extract_signed(blob, ctx?),
		_ => None,
	}
}

/// EVM self-contained `transact_blackchain`: the call args ARE the SCALE-encoded
/// `BlackChainTransaction`, i.e. exactly the bytes `verify_pqc_transaction` accepts.
fn extract_evm(blob: &[u8]) -> Option<PqcBatchItem> {
	let (&pallet, rest) = blob.get(1..)?.split_first()?;
	let (&call, args) = rest.split_first()?;
	if (pallet, call) == (ETHEREUM_PALLET_INDEX, TRANSACT_BLACKCHAIN_CALL) {
		Some(PqcBatchItem::Transaction(args.to_vec()))
	} else {
		None
	}
}

/// A PQC-signed Substrate extrinsic (any pallet call). Layout after the preamble:
/// `from(20) ‖ PqcSignature{ pub_key: Vec<u8>, signature: Vec<u8> } ‖ extra ‖ call`,
/// where `extra = Era ‖ Compact(nonce) ‖ Compact(tip)`.
fn extract_signed(blob: &[u8], ctx: &SignedCtx) -> Option<PqcBatchItem> {
	let mut p = 1usize; // after the 0x84 preamble
	p = p.checked_add(20)?; // skip the signer address (recovered from the sig anyway)

	// PqcSignature { pub_key, signature } — two length-prefixed Vec<u8> in field order.
	let (pk_len, after_pk_len) = read_compact(blob, p)?;
	let pk_end = after_pk_len.checked_add(pk_len as usize)?;
	let pub_key = blob.get(after_pk_len..pk_end)?.to_vec();
	if pub_key.len() != COMPOSITE_PK_SIZE {
		return None;
	}
	let (sig_len, after_sig_len) = read_compact(blob, pk_end)?;
	let sig_end = after_sig_len.checked_add(sig_len as usize)?;
	let signature = blob.get(after_sig_len..sig_end)?.to_vec();
	if signature.len() != COMPOSITE_SIG_SIZE {
		return None;
	}

	// extra = Era ‖ Compact(nonce) ‖ Compact(tip). Only immortal era (0x00) can be
	// reconstructed here, since a mortal era's implicit block hash isn't the genesis.
	let extra_start = sig_end;
	if *blob.get(extra_start)? != 0x00 {
		return None;
	}
	let (_nonce, after_nonce) = read_compact(blob, extra_start + 1)?;
	let (_tip, call_start) = read_compact(blob, after_nonce)?;
	let extra_bytes = blob.get(extra_start..call_start)?;
	let call_bytes = blob.get(call_start..)?;

	// Signing payload = call ‖ extra ‖ implicit (additional-signed). For an immortal
	// era the CheckEra implicit is the genesis hash, matching CheckGenesis.
	let mut payload =
		Vec::with_capacity(call_bytes.len() + extra_bytes.len() + 4 + 4 + 32 + 32);
	payload.extend_from_slice(call_bytes);
	payload.extend_from_slice(extra_bytes);
	payload.extend_from_slice(&ctx.spec_version.to_le_bytes());
	payload.extend_from_slice(&ctx.tx_version.to_le_bytes());
	payload.extend_from_slice(&ctx.genesis);
	payload.extend_from_slice(&ctx.genesis);

	// `PqcSignature::verify` prepends the domain tag to the payload the runtime hands
	// it, and `SignedPayload` blake2_256-hashes the payload when it exceeds 256 bytes.
	let mut message = Vec::with_capacity(EXTRINSIC_DOMAIN_TAG.len() + payload.len().min(64));
	message.extend_from_slice(EXTRINSIC_DOMAIN_TAG);
	if payload.len() > 256 {
		message.extend_from_slice(BlakeTwo256::hash(&payload).as_bytes());
	} else {
		message.extend_from_slice(&payload);
	}

	Some(PqcBatchItem::Message {
		message,
		signature,
		pub_key,
	})
}

/// Decode a SCALE compact at `blob[p]`, returning `(value, offset_after)`.
fn read_compact(blob: &[u8], p: usize) -> Option<(u64, usize)> {
	let first = *blob.get(p)?;
	match first & 0b11 {
		0b00 => Some(((first >> 2) as u64, p + 1)),
		0b01 => {
			let raw = (first as u16) | ((*blob.get(p + 1)? as u16) << 8);
			Some(((raw >> 2) as u64, p + 2))
		}
		0b10 => {
			let raw = (first as u32)
				| ((*blob.get(p + 1)? as u32) << 8)
				| ((*blob.get(p + 2)? as u32) << 16)
				| ((*blob.get(p + 3)? as u32) << 24);
			Some(((raw >> 2) as u64, p + 4))
		}
		_ => {
			let len = ((first >> 2) + 4) as usize;
			let mut v: u64 = 0;
			for i in 0..len {
				v |= (*blob.get(p + 1 + i)? as u64) << (8 * i);
			}
			Some((v, p + 1 + len))
		}
	}
}

#[async_trait::async_trait]
impl<B, I, C> BlockImport<B> for PqcPrewarmBlockImport<B, I, C>
where
	B: BlockT,
	I: BlockImport<B> + Send + Sync,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync,
	C::Api: Core<B>,
{
	type Error = I::Error;

	async fn check_block(
		&self,
		block: BlockCheckParams<B>,
	) -> Result<ImportResult, Self::Error> {
		self.inner.check_block(block).await
	}

	async fn import_block(
		&self,
		block: BlockImportParams<B>,
	) -> Result<ImportResult, Self::Error> {
		// Warm the cache, snapshotting cache stats around the pre-pass and around
		// the inner import (= block execution) so the two phases can be compared:
		// the pre-pass fills the cache, execution should then be served from it.
		let phases = block.body.as_ref().map(|body| {
			let parent = *block.header.parent_hash();
			let before = cache_stats();
			self.warm(parent, body);
			(before, cache_stats())
		});

		let result = self.inner.import_block(block).await;

		if let Some(((h0, m0), (h1, m1))) = phases {
			let (h2, m2) = cache_stats();
			log::debug!(
				target: "pqc_prewarm",
				"verify cache — pre-pass: +{} hit / +{} miss; execution: +{} hit / +{} miss",
				h1.saturating_sub(h0), m1.saturating_sub(m0),
				h2.saturating_sub(h1), m2.saturating_sub(m1),
			);
		}
		result
	}
}
