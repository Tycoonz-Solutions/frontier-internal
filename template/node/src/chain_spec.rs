use std::{collections::BTreeMap, str::FromStr};

use hex_literal::hex;
// Substrate
use sc_chain_spec::{ChainType, Properties};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{Pair, Public, H160, U256};
use sp_runtime::traits::{IdentifyAccount, Verify};
// Frontier
use frontier_template_runtime::{AccountId, Balance, SS58Prefix, Signature, WASM_BINARY};

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{seed}"), None)
		.expect("static values are valid; qed")
		.public()
}

#[allow(dead_code)]
type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
/// For use with `AccountId32`, `dead_code` if `AccountId20`.
#[allow(dead_code)]
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenDecimals".into(), 18.into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties.insert("isEthereum".into(), true.into());
	properties
}

const UNITS: Balance = 1_000_000_000_000_000_000;

/// PQC-controllable genesis wallets (H160, no `0x` prefix), funded at genesis.
/// Derived from the `pqc-tx-test` development mnemonic (empty passphrase) at HD
/// path `m/44'/60'/0'/0'/<index>'`. Index 0 is the long-standing dev PQC wallet.
/// Regenerate/extend with `pqc-tx-test --gen-wallets <N>`.
const PQC_GENESIS_WALLETS: [&str; 4] = [
	"ff0341100577b6cf676cc8fb8d1bf654b0a478ba", // index 0
	"14f69e800a8cf85275ec6629e3f5910cd92ab832", // index 1
	"56cb6b549e19eb222840dbf7af8083a6b01d6e6a", // index 2
	"5cac4da80f5dcc347b45814d1273246951c1d1ce", // index 3
];

/// The dev/local PQC wallets, each funded with the max balance. These are derived
/// from the PUBLIC `pqc-tx-test` mnemonic — dev/local convenience only, NEVER a
/// public network.
fn dev_pqc_wallets() -> Vec<(H160, U256)> {
	let bal = U256::from_str("0xffffffffffffffffffffffffffffffff")
		.expect("internal U256 is valid; qed");
	PQC_GENESIS_WALLETS
		.iter()
		.map(|w| (H160::from_str(w).expect("internal PQC wallet H160 is valid; qed"), bal))
		.collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC TESTNET placeholders — MUST be replaced before standing up a shared net.
// Nothing here may be derived from a public seed/mnemonic.
// ─────────────────────────────────────────────────────────────────────────────

/// PQC Root admin for the public testnet. REPLACE with a team-controlled address
/// generated offline (`pqc-tx-test --gen-wallets 1`) whose private key is NOT the
/// public dev mnemonic. Whoever holds this key controls set_code / governance / key
/// rotation. Left as a burn address so a misconfigured launch fails the assert in
/// `public_testnet_config` rather than shipping a publicly-controllable admin.
///
/// Set 2026-08-11 to a FRESH, non-dev-mnemonic PQC wallet (index 0). The seed lives
/// in the gitignored `.testnet-secrets/` and was generated in-session — treat as a
/// throwaway bootstrap key and regenerate offline before any long-lived/public net.
const TESTNET_ADMIN_KEY: &str = "5601583578328b683b1d232820f0dd58d1ea88d1";

/// Faucet / initial funded PQC account for the public testnet (finite balance, never
/// U256::MAX). Index 1 of the same fresh testnet mnemonic (see `.testnet-secrets/`).
const TESTNET_FAUCET: &str = "d8546f36f7b25474ea4a834597376a9ca60eab78";

pub fn development_config(enable_manual_seal: bool) -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Development")
		.with_id("dev")
		.with_chain_type(ChainType::Development)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// Dev PQC Root admin = index-0 dev wallet. Public-mnemonic-derived: fine for
			// dev, NEVER for a shared network (use `public_testnet_config`).
			H160::from_str(PQC_GENESIS_WALLETS[0]).expect("internal H160 is valid; qed"),
			// Dev PQC wallets funded with max balance via the EVM genesis.
			dev_pqc_wallets(),
			// Sudo key — nominal only; sudo is inert on this PQC-only chain.
			AccountId::from(hex!("ff0341100577b6cf676cc8fb8d1bf654b0a478ba")),
			// No Substrate/Balances-layer endowments: every spendable account is a
			// PQC wallet seeded through the EVM genesis (see PQC_GENESIS_WALLETS).
			// Classical secp256k1 dev accounts are removed (they can't spend on a
			// PQC-only chain).
			vec![],
			// Initial PoA authorities (consensus session keys — sr25519/ed25519,
			// unrelated to transaction signing; required to author & finalize).
			vec![authority_keys_from_seed("Alice")],
			// Ethereum chain ID
			SS58Prefix::get() as u64,
			enable_manual_seal,
		))
		.build()
}

pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Local Testnet")
		.with_id("local_testnet")
		.with_chain_type(ChainType::Local)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// Dev PQC Root admin = index-0 dev wallet (public-mnemonic — local only).
			H160::from_str(PQC_GENESIS_WALLETS[0]).expect("internal H160 is valid; qed"),
			dev_pqc_wallets(),
			// Sudo key — nominal only; sudo is inert on this PQC-only chain.
			AccountId::from(hex!("ff0341100577b6cf676cc8fb8d1bf654b0a478ba")),
			// No Substrate/Balances-layer endowments (PQC-only, see development_config).
			vec![],
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			42,
			false,
		))
		.build()
}

/// Public testnet spec (`--chain testnet`), `ChainType::Live`.
///
/// ⚠ This is a SCAFFOLD. Before standing up a shared testnet you MUST replace, with
/// team-controlled values that are NOT derived from any public seed:
///   * `TESTNET_ADMIN_KEY` — the PQC Root admin (`pqc-tx-test --gen-wallets 1`);
///   * `TESTNET_FAUCET`     — the funded/faucet account;
///   * the validator session keys below (currently the well-known //Alice//Bob).
///
/// The function asserts the admin key is no longer the burn-address placeholder, so
/// a misconfigured launch fails fast rather than shipping with a dead/there-is-no
/// admin. Funding is finite (NOT `U256::MAX`).
pub fn public_testnet_config() -> ChainSpec {
	let admin = H160::from_str(TESTNET_ADMIN_KEY).expect("TESTNET_ADMIN_KEY is valid hex; qed");
	let placeholder =
		H160::from_str("000000000000000000000000000000000000dead").expect("valid; qed");
	assert_ne!(
		admin, placeholder,
		"TESTNET_ADMIN_KEY is still the placeholder burn address — set a team-controlled \
		 PQC admin (pqc-tx-test --gen-wallets 1) before building the public testnet spec"
	);
	let faucet = H160::from_str(TESTNET_FAUCET).expect("TESTNET_FAUCET is valid hex; qed");
	// Finite faucet balance (10M UNITS), never U256::MAX.
	let faucet_balance = U256::from(10_000_000u128 * UNITS);

	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("BlackChain Testnet")
		.with_id("blackchain_testnet")
		.with_chain_type(ChainType::Live)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			admin,
			vec![(faucet, faucet_balance)],
			// Sudo key — nominal only (pallet-sudo inert); mirror the faucet.
			AccountId::from(faucet),
			vec![],
			// ⚠ REPLACE with real, team-generated validator session keys before launch.
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			42,
			false,
		))
		.build()
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	// PQC Root admin address (controls set_code / governance via pallet-blackchain-sudo).
	admin_key: H160,
	// Funded PQC EVM accounts (`address`, `balance`). Spendable via `transact_blackchain`.
	pqc_wallets: Vec<(H160, U256)>,
	sudo_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	let evm_accounts = {
		let mut map = BTreeMap::new();

		// ── BlackChain PQC genesis wallets ──────────────────────────────────
		// This is a PQC-only chain: classical secp256k1 accounts (the old Alice /
		// CI-runner dev accounts, Moonbeam-style Alith/Baltathar/... accounts) can
		// NOT spend, because no post-quantum keypair hashes to their address. They
		// have been removed. Every funded account below is derived from a real PQC
		// composite keypair and is spendable via `transact_blackchain`.
		//
		// All wallets are restorable from the development mnemonic used by the
		// `pqc-tx-test` tool (empty passphrase), at HD path m/44'/60'/0'/0'/<index>':
		//   index 0 -> 0xff0341100577b6cf676cc8fb8d1bf654b0a478ba
		//   index 1 -> 0x14f69e800a8cf85275ec6629e3f5910cd92ab832
		//   index 2 -> 0x56cb6b549e19eb222840dbf7af8083a6b01d6e6a
		//   index 3 -> 0x5cac4da80f5dcc347b45814d1273246951c1d1ce
		// Regenerate/extend with: `pqc-tx-test --gen-wallets <N>`.
		for (addr, balance) in &pqc_wallets {
			map.insert(
				*addr,
				fp_evm::GenesisAccount {
					balance: *balance,
					code: Default::default(),
					nonce: Default::default(),
					storage: Default::default(),
				},
			);
		}

		map.insert(
			// H160 address for benchmark usage (fixture with dummy code; not a wallet).
			H160::from_str("1000000000000000000000000000000000000001")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::from(1_000_000_000_000_000_000_000_000u128),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	serde_json::json!({
		"sudo": { "key": Some(sudo_key) },
		"balances": {
			"balances": endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1_000_000 * UNITS))
				.collect::<Vec<_>>()
		},
		"aura": { "authorities": initial_authorities.iter().map(|x| (x.0.clone())).collect::<Vec<_>>() },
		"grandpa": { "authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>() },
		"evmChainId": { "chainId": chain_id },
		"evm": { "accounts": evm_accounts },
		"manualSeal": { "enable": enable_manual_seal },
		// PQC-authenticated admin key controls Root (set_code, governance, key
		// rotation) via pallet-blackchain-sudo, since classic signed extrinsics (and
		// thus pallet-sudo) are disabled. Supplied per-network by the caller.
		"blackchainSudo": { "adminKey": format!("0x{:x}", admin_key) }
	})
}
