//! Synthetic-block harness (dev tool, `.journals/opcode-max-cg-2026-09.md`): build a synthetic block + full-trie witness
//! from a JSON spec, fix header fields from native validation errors, write
//! witness.json / block.rlp / meta.json / receipts.json into --out.
use alloy_consensus::{
    transaction::SignableTransaction, BlockBody, EthereumTxEnvelope, Header, TxEip4844, TxLegacy,
};
use alloy_primitives::{b256, keccak256, Address, Bytes, TxKind, B256, U256};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

const EMPTY_ROOT_HASH: B256 =
    b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
const EMPTY_REQUESTS_HASH: B256 =
    b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
const EMPTY_CODE_HASH: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

#[derive(Deserialize)]
struct Spec {
    number: u64,
    timestamp: u64,
    gas_limit: u64,
    #[serde(default)]
    contracts: Vec<ContractSpec>,
    txs: Vec<TxSpec>,
    #[serde(default)]
    ancestors: u64,
    /// Deep-trie fillers: for each target key, 15 sibling leaves per level 0..depth.
    #[serde(default)]
    deep: Vec<DeepSpec>,
}

#[derive(Deserialize)]
struct DeepSpec {
    /// Account addresses whose state-trie paths get `depth` full branch levels.
    #[serde(default)]
    accounts: Vec<Address>,
    /// (contract, slots): storage-trie paths with `depth` full branch levels.
    #[serde(default)]
    storage: Vec<(Address, Vec<U256>)>,
    depth: usize,
}

/// Insert 15 filler leaves per level so `key`'s path has `depth` 16-child branches.
fn add_fillers(trie: &mut zeth_mpt::Trie, key: B256, depth: usize, value: &[u8]) {
    for level in 0..depth {
        let nib = |k: &B256, i: usize| (k[i / 2] >> (4 * (1 - (i % 2) as u32))) & 0xf;
        for n in 0u8..16 {
            if n == nib(&key, level) {
                continue;
            }
            let mut fk = keccak256((key, level as u64, n as u64).abi_encode_packed_hack());
            // copy the shared prefix (level nibbles) then force nibble `level` = n
            for i in 0..level {
                let v = nib(&key, i);
                if i % 2 == 0 {
                    fk[i / 2] = (fk[i / 2] & 0x0f) | (v << 4);
                } else {
                    fk[i / 2] = (fk[i / 2] & 0xf0) | v;
                }
            }
            if level % 2 == 0 {
                fk[level / 2] = (fk[level / 2] & 0x0f) | (n << 4);
            } else {
                fk[level / 2] = (fk[level / 2] & 0xf0) | n;
            }
            trie.insert(fk, value.to_vec());
        }
    }
}

trait PackedHack {
    fn abi_encode_packed_hack(&self) -> Vec<u8>;
}
impl PackedHack for (B256, u64, u64) {
    fn abi_encode_packed_hack(&self) -> Vec<u8> {
        let mut v = self.0.to_vec();
        v.extend_from_slice(&self.1.to_le_bytes());
        v.extend_from_slice(&self.2.to_le_bytes());
        v
    }
}

#[derive(Deserialize)]
struct ContractSpec {
    address: Address,
    #[serde(default)]
    code: Bytes,
    #[serde(default)]
    balance: U256,
    #[serde(default)]
    nonce: u64,
    #[serde(default)]
    storage: BTreeMap<U256, U256>,
}

#[derive(Deserialize)]
struct TxSpec {
    to: Option<Address>,
    #[serde(default)]
    data: Bytes,
    gas: u64,
    #[serde(default)]
    value: U256,
}

fn rlp_account(nonce: u64, balance: U256, storage_root: B256, code_hash: B256) -> Vec<u8> {
    use alloy_rlp::Encodable;
    let payload = nonce.length() + balance.length() + storage_root.length() + code_hash.length();
    let mut out = Vec::with_capacity(payload + 3);
    alloy_rlp::Header {
        list: true,
        payload_length: payload,
    }
    .encode(&mut out);
    nonce.encode(&mut out);
    balance.encode(&mut out);
    storage_root.encode(&mut out);
    code_hash.encode(&mut out);
    out
}

fn parse_got(msg: &str) -> Option<String> {
    let i = msg.find("got ")?;
    let rest = &msg[i + 4..];
    let end = rest.find([',', '\n', ' ']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let spec_path = &args[1];
    let out = std::path::Path::new(&args[2]);
    std::fs::create_dir_all(out)?;
    let spec: Spec = serde_json::from_slice(&std::fs::read(spec_path)?)?;

    // Sender key: fixed scalar.
    let sk = k256::ecdsa::SigningKey::from_bytes(&[0x11u8; 32].into())?;
    let vk = sk.verifying_key();
    let pk_point = vk.to_encoded_point(false);
    let pk_bytes: [u8; 65] = pk_point.as_bytes().try_into().unwrap();
    let sender = Address::from_slice(&keccak256(&pk_bytes[1..])[12..]);

    // System contracts (mainnet bytecode fetched via eth_getCode, empty storage).
    let mut accounts: Vec<ContractSpec> = Vec::new();
    for (addr, file) in [
        (
            "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02",
            "/tmp/opcg/code_0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02.json",
        ),
        (
            "0x0000F90827F1C53a10cb7A02335B175320002935",
            "/tmp/opcg/code_0x0000F90827F1C53a10cb7A02335B175320002935.json",
        ),
        (
            "0x00000961Ef480Eb55e80D19ad83579A64c007002",
            "/tmp/opcg/code_0x00000961Ef480Eb55e80D19ad83579A64c007002.json",
        ),
        (
            "0x0000BBdDc7CE488642fb579F8B00f3a590007251",
            "/tmp/opcg/code_0x0000BBdDc7CE488642fb579F8B00f3a590007251.json",
        ),
    ] {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(file)?)?;
        let code: Bytes = v["result"].as_str().unwrap().parse()?;
        accounts.push(ContractSpec {
            address: addr.parse()?,
            code,
            balance: U256::ZERO,
            nonce: 1,
            storage: BTreeMap::new(),
        });
    }
    accounts.push(ContractSpec {
        address: sender,
        code: Bytes::new(),
        balance: U256::from(1u128 << 100),
        nonce: 0,
        storage: BTreeMap::new(),
    });
    accounts.extend(spec.contracts);

    // Full pre-state trie + storage tries.
    let mut state = zeth_mpt::Trie::default();
    let mut nodes: Vec<Bytes> = Vec::new();
    let mut codes: Vec<Bytes> = Vec::new();
    let mut seen_codes = std::collections::HashSet::new();
    let filler_account = rlp_account(0, U256::from(1), EMPTY_ROOT_HASH, EMPTY_CODE_HASH);
    let mut deep_storage: BTreeMap<Address, (usize, Vec<U256>)> = BTreeMap::new();
    for d in &spec.deep {
        for (a, slots) in &d.storage {
            let e = deep_storage.entry(*a).or_insert((d.depth, Vec::new()));
            e.1.extend(slots.iter().copied());
        }
    }
    for acct in &accounts {
        let mut storage = zeth_mpt::Trie::default();
        let has_deep = deep_storage.get(&acct.address);
        if let Some((depth, slots)) = has_deep {
            for slot in slots {
                add_fillers(
                    &mut storage,
                    keccak256(slot.to_be_bytes::<32>()),
                    *depth,
                    &alloy_rlp::encode(U256::from(1)),
                );
            }
        }
        for (slot, value) in &acct.storage {
            if value.is_zero() {
                continue;
            }
            storage.insert(
                keccak256(slot.to_be_bytes::<32>()),
                alloy_rlp::encode(value),
            );
        }
        let storage_used = !acct.storage.is_empty() || has_deep.is_some();
        let storage_root = if storage_used {
            storage.hash_slow()
        } else {
            EMPTY_ROOT_HASH
        };
        if storage_used {
            nodes.extend(storage.rlp_nodes());
        }
        let code_hash = if acct.code.is_empty() {
            EMPTY_CODE_HASH
        } else {
            keccak256(&acct.code)
        };
        if !acct.code.is_empty() && seen_codes.insert(code_hash) {
            codes.push(acct.code.clone());
        }
        state.insert(
            keccak256(acct.address),
            rlp_account(acct.nonce, acct.balance, storage_root, code_hash),
        );
    }
    for d in &spec.deep {
        for a in &d.accounts {
            add_fillers(&mut state, keccak256(a), d.depth, &filler_account);
        }
    }
    let pre_root = state.hash_slow();
    let mut state_nodes = state.rlp_nodes();
    state_nodes.extend(nodes);
    // Dedupe, keep root first.
    let mut seen = std::collections::HashSet::new();
    state_nodes.retain(|n| seen.insert(keccak256(n)));

    // Ancestor headers: parent (+ optional extra ancestors for BLOCKHASH).
    let mut headers: Vec<Header> = Vec::new();
    let ancestor_count = spec.ancestors.max(1);
    let mut prev_hash = B256::ZERO;
    for i in 0..ancestor_count {
        let number = spec.number - ancestor_count + i;
        let h = Header {
            parent_hash: prev_hash,
            ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
            beneficiary: Address::repeat_byte(0xbe),
            state_root: pre_root,
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            number,
            gas_limit: spec.gas_limit,
            gas_used: spec.gas_limit / 2,
            timestamp: spec.timestamp - 12 * (ancestor_count - i),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        prev_hash = h.hash_slow();
        headers.push(h);
    }
    let parent = headers.last().unwrap().clone();

    // Transactions (legacy, EIP-155, same sender, sequential nonces).
    let mut txs: Vec<EthereumTxEnvelope<TxEip4844>> = Vec::new();
    let mut signers: Vec<jeth_core::UncompressedPublicKey> = Vec::new();
    for (i, t) in spec.txs.iter().enumerate() {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: i as u64,
            gas_price: 7,
            gas_limit: t.gas,
            to: match t.to {
                Some(a) => TxKind::Call(a),
                None => TxKind::Create,
            },
            value: t.value,
            input: t.data.clone(),
        };
        let hash = tx.signature_hash();
        let (sig, recid) = sk.sign_prehash_recoverable(hash.as_slice())?;
        let (sig, recid) = match sig.normalize_s() {
            Some(n) => (
                n,
                k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1).unwrap(),
            ),
            None => (sig, recid),
        };
        let r = U256::from_be_slice(&sig.r().to_bytes());
        let s = U256::from_be_slice(&sig.s().to_bytes());
        let signature = alloy_primitives::Signature::new(r, s, recid.is_y_odd());
        txs.push(EthereumTxEnvelope::Legacy(tx.into_signed(signature)));
        signers.push(jeth_core::UncompressedPublicKey(pk_bytes));
    }

    let mut header = Header {
        parent_hash: parent.hash_slow(),
        ommers_hash: parent.ommers_hash,
        beneficiary: Address::repeat_byte(0xbe),
        state_root: B256::ZERO,
        transactions_root: alloy_consensus::proofs::calculate_transaction_root(&txs),
        receipts_root: EMPTY_ROOT_HASH,
        number: spec.number,
        gas_limit: spec.gas_limit,
        gas_used: 0,
        timestamp: spec.timestamp,
        base_fee_per_gas: Some(7),
        withdrawals_root: Some(EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::repeat_byte(0x42)),
        requests_hash: Some(EMPTY_REQUESTS_HASH),
        mix_hash: B256::repeat_byte(0x77),
        ..Default::default()
    };

    let witness = jeth_core::ExecutionWitness {
        state: state_nodes,
        codes,
        keys: vec![],
        headers: headers
            .iter()
            .map(|h| Bytes::from(alloy_rlp::encode(h)))
            .collect(),
    };

    let chain_spec = std::sync::Arc::new(jeth_core::mainnet_spec());
    let mut receipts_out = None;
    for attempt in 0..12 {
        let block = alloy_consensus::Block {
            header: header.clone(),
            body: BlockBody {
                transactions: txs.clone(),
                ommers: vec![],
                withdrawals: Some(Default::default()),
            },
        };
        let recovered = jeth_core::recover_block(block, signers.clone())
            .map_err(|e| anyhow::anyhow!("recover: {e}"))?;
        let evm_config = jeth_core::EthEvmConfig::new(chain_spec.clone());
        match jeth_core::validation::validate_recovered_pertx(
            recovered,
            witness.clone(),
            chain_spec.clone(),
            evm_config,
        ) {
            Ok(v) => {
                receipts_out = Some(v);
                break;
            }
            Err(e) => {
                let msg = e.to_string();
                eprintln!("attempt {attempt}: {}", msg.lines().next().unwrap_or(""));
                let got = parse_got(&msg);
                if msg.contains("block gas used mismatch") {
                    header.gas_used = got.context("gas got")?.parse()?;
                } else if msg.contains("receipt root mismatch") {
                    header.receipts_root = got.context("rr got")?.parse()?;
                } else if msg.contains("bloom filter mismatch") {
                    header.logs_bloom = got.context("bloom got")?.parse()?;
                } else if msg.contains("requests hash") {
                    header.requests_hash = Some(got.context("rh got")?.parse()?);
                } else if msg.contains("mismatched post-state root") {
                    let tok = msg
                        .split("root: ")
                        .nth(1)
                        .unwrap()
                        .split_whitespace()
                        .next()
                        .unwrap();
                    header.state_root = tok.parse()?;
                } else {
                    anyhow::bail!("unhandled validation error: {msg}");
                }
            }
        }
    }
    let validated = receipts_out.context("header fixpoint not reached")?;
    let block = alloy_consensus::Block {
        header: header.clone(),
        body: BlockBody {
            transactions: txs.clone(),
            ommers: vec![],
            withdrawals: Some(Default::default()),
        },
    };
    let block_rlp = alloy_rlp::encode(&block);
    std::fs::write(out.join("block.rlp"), &block_rlp)?;
    std::fs::write(out.join("witness.json"), serde_json::to_vec(&witness)?)?;
    std::fs::write(
        out.join("meta.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "block_number": spec.number, "timestamp": spec.timestamp, "gas_limit": spec.gas_limit,
            "gas_used": validated.gas_used, "tx_count": txs.len(), "synthetic": true,
        }))?,
    )?;
    let mut prev = 0u64;
    let rows: Vec<serde_json::Value> = validated
        .receipts
        .iter()
        .map(|r| {
            let g = r.cumulative_gas_used - prev;
            prev = r.cumulative_gas_used;
            serde_json::json!({"success": r.success, "gas_used": g, "logs": r.logs.len()})
        })
        .collect();
    std::fs::write(
        out.join("receipts.json"),
        serde_json::to_string_pretty(&rows)?,
    )?;
    println!(
        "block {} gas_used {} txs {} witness nodes {} codes {} → {}",
        spec.number,
        validated.gas_used,
        txs.len(),
        witness.state.len(),
        witness.codes.len(),
        out.display()
    );
    for (i, r) in rows.iter().enumerate() {
        println!("  tx{i}: success={} gas={}", r["success"], r["gas_used"]);
    }
    Ok(())
}
