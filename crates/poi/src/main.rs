#![no_main]

use core::panic;
use std::{collections::HashSet, str::FromStr, sync::Arc};

use alloy_consensus::{Header, Transaction, TxEnvelope};
use alloy_eips::{
    eip2718::Decodable2718, eip4844::DATA_GAS_PER_BLOB, eip7840::BlobParams,
    merge::SLOT_DURATION_SECS,
};
use alloy_primitives::{keccak256, Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount};
use eth_trie::{EthTrie, MemoryDB, Trie};
use eyre::{eyre, Result};
use taiyi_zkvm_types::{types::*, utils::*};

sp1_zkvm::entrypoint!(main);

enum VerificationResult {
    Success,
    Failed, // Verification failed but this is a valid outcome
}

fn create_public_values(
    inclusion_block_header: &Header,
    inclusion_block_hash: B256,
    underwriter_address: Address,
    preconf_signature: &PrimitiveSignature,
    genesis_timestamp: u64,
    taiyi_core: Address,
) -> PublicValuesStruct {
    PublicValuesStruct {
        proofBlockTimestamp: inclusion_block_header.timestamp,
        proofBlockHash: inclusion_block_hash,
        proofBlockNumber: inclusion_block_header.number,
        underwriterAddress: underwriter_address,
        proofSignature: preconf_signature.as_bytes().to_vec().into(),
        genesisTimestamp: genesis_timestamp,
        taiyiCore: taiyi_core,
    }
}

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

#[allow(clippy::too_many_arguments)]
fn run_poi_verification(
    preconf: String,
    preconf_signature_str: String,
    is_type_a: bool,
    inclusion_block_header_str: String,
    inclusion_block_hash: B256,
    previous_block_header_str: String,
    previous_block_hash: B256,
    underwriter_address: Address,
    genesis_timestamp: u64,
    taiyi_core: Address,
) -> Result<VerificationResult> {
    println!("DEBUG: Running poi verification logic");

    println!(
        "DEBUG: Processing {} request for underwriter: {:?}",
        if is_type_a { "Type A" } else { "Type B" },
        underwriter_address
    );
    println!(
        "DEBUG: Inclusion block hash: {:?}, number: {}",
        inclusion_block_hash,
        serde_json::from_str::<Header>(&inclusion_block_header_str)
            .map(|h| h.number)
            .unwrap_or_default()
    );

    let inclusion_block_header = serde_json::from_str::<Header>(&inclusion_block_header_str)
        .map_err(|e| {
            println!("ERROR: Failed to parse inclusion block header: {}", e);
            eyre!("Invalid inclusion block header JSON format: {}", e)
        })?;
    println!(
        "DEBUG: Successfully parsed inclusion block header, number: {}",
        inclusion_block_header.number
    );

    let previous_block_header = serde_json::from_str::<Header>(&previous_block_header_str)
        .map_err(|e| {
            println!("ERROR: Failed to parse previous block header: {}", e);
            eyre!("Invalid previous block header JSON format: {}", e)
        })?;
    println!(
        "DEBUG: Successfully parsed previous block header, number: {}",
        previous_block_header.number
    );

    assert_eq!(
        inclusion_block_header.hash_slow(),
        inclusion_block_hash,
        "Inclusion block header hash mismatch: computed {:?} != expected {:?}",
        inclusion_block_header.hash_slow(),
        inclusion_block_hash
    );
    assert_eq!(
        previous_block_header.hash_slow(),
        previous_block_hash,
        "Previous block header hash mismatch: computed {:?} != expected {:?}",
        previous_block_header.hash_slow(),
        previous_block_hash
    );
    assert_eq!(
        inclusion_block_header.parent_hash, previous_block_hash,
        "Block chain continuity broken: inclusion block parent {:?} != previous block hash {:?}",
        inclusion_block_header.parent_hash, previous_block_hash
    );

    let preconf_signature = PrimitiveSignature::from_str(&preconf_signature_str).map_err(|e| {
        println!("ERROR: Failed to parse preconf signature: {}", e);
        eyre!("Invalid preconf signature format: {}", e)
    })?;
    println!("DEBUG: Successfully parsed preconf signature");

    if is_type_a {
        println!("DEBUG: Processing Type A preconf request");
        let preconf_req_a = serde_json::from_str::<PreconfTypeA>(&preconf).map_err(|e| {
            println!("ERROR: Failed to parse Type A preconf request: {}", e);
            eyre!("Invalid Type A preconf request JSON format: {}", e)
        })?;
        println!("DEBUG: Successfully parsed Type A preconf request");

        let txs = preconf_req_a.preconf.clone().transactions;
        println!("DEBUG: Type A request contains {} transactions", txs.len());

        let chain_id = match txs.first() {
            Some(tx) => match tx.chain_id() {
                Some(id) => {
                    println!("DEBUG: Chain ID from transaction: {}", id);
                    id
                }
                None => {
                    println!("ERROR: Failed to get chain ID from transaction");
                    return Err(eyre!("Transaction missing chain ID"));
                }
            },
            None => {
                println!("ERROR: No transactions in Type A request");
                return Err(eyre!("Type A request contains no transactions"));
            }
        };

        let recovered_address = preconf_signature
            .recover_address_from_prehash(&preconf_req_a.preconf.digest(chain_id))
            .map_err(|e| {
                println!("ERROR: Failed to recover address from signature: {:?}", e);
                eyre!("Failed to recover address from preconf signature: {:?}", e)
            })?;
        println!("DEBUG: Successfully recovered address from signature: {:?}", recovered_address);

        assert!(
            underwriter_address == recovered_address,
            "Underwriter address mismatch: expected {:?}, got {:?}",
            underwriter_address,
            recovered_address
        );

        println!(
            "DEBUG: Verifying target slot: expected {}, actual {}",
            preconf_req_a.preconf.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );
        assert_eq!(
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp),
            preconf_req_a.preconf.target_slot,
            "Target slot mismatch: expected {}, got {}",
            preconf_req_a.preconf.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );

        println!("DEBUG: Starting account verification for {} transactions", txs.len());
        for (index, tx) in txs.iter().enumerate() {
            println!("DEBUG: Verifying account for transaction {}/{}", index + 1, txs.len());
            let account_merkle_proof = preconf_req_a.account_merkle_proof[index].clone();
            let account_key = account_merkle_proof.address;

            let tx_signer = tx.recover_signer().map_err(|e| {
                println!("ERROR: Failed to recover signer from transaction {}: {:?}", index, e);
                eyre!("Failed to recover signer from transaction {}: {:?}", index, e)
            })?;
            println!("DEBUG: Successfully recovered signer from transaction: {:?}", tx_signer);

            assert_eq!(
                account_key, tx_signer,
                "Account key mismatch for tx {}: expected {:?}, got {:?}",
                index, account_key, tx_signer
            );

            let account = TrieAccount {
                nonce: account_merkle_proof.nonce,
                balance: account_merkle_proof.balance,
                storage_root: account_merkle_proof.storage_hash,
                code_hash: account_merkle_proof.code_hash,
            };
            println!(
                "DEBUG: Account state - nonce: {}, balance: {}",
                account.nonce, account.balance
            );

            verify_proof(
                previous_block_header.state_root,
                Nibbles::unpack(keccak256(account_key)),
                Some(alloy_rlp::encode(account)),
                &account_merkle_proof.account_proof,
            )
            .map_err(|e| {
                println!("ERROR: Account state verification failed for tx {}: {:?}", index, e);
                eyre!("Account state verification failed for tx {}: {:?}", index, e)
            })?;
            println!("DEBUG: Account state verification successful for tx {}", index);

            if account.nonce > tx.nonce() {
                println!(
                    "DEBUG: Account nonce ({}) > tx nonce ({}), verification failed",
                    account.nonce,
                    tx.nonce()
                );
                return Ok(VerificationResult::Failed);
            }

            if tx.is_eip4844() {
                println!("DEBUG: Processing EIP4844 transaction");
                let tx_eip4844 = tx.as_eip4844().ok_or_else(|| {
                    println!("ERROR: Failed to parse EIP4844 transaction");
                    eyre!("Transaction identified as EIP4844 but failed to parse as such")
                })?;
                println!("DEBUG: Successfully parsed EIP4844 transaction");

                let blob_fee =
                    inclusion_block_header.blob_fee(BlobParams::prague()).ok_or_else(|| {
                        println!("ERROR: Failed to get blob fee from inclusion block header");
                        eyre!("Failed to get blob fee from inclusion block header")
                    })?;
                println!("DEBUG: Blob fee: {}", blob_fee);

                let blob_hashes_len =
                    tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len();
                println!("DEBUG: Transaction has {} blob hashes", blob_hashes_len);

                let base_fee = inclusion_block_header.base_fee_per_gas.ok_or_else(|| {
                    println!("ERROR: Failed to get base fee from inclusion block header");
                    eyre!("Failed to get base fee from inclusion block header")
                })?;
                println!("DEBUG: Base fee: {}", base_fee);

                let priority_fee = tx.max_priority_fee_per_gas().ok_or_else(|| {
                    println!("ERROR: Failed to get priority fee from transaction");
                    eyre!("Failed to get priority fee from transaction")
                })?;
                println!("DEBUG: Priority fee: {}", priority_fee);

                let required_balance = U256::from(
                    blob_fee * DATA_GAS_PER_BLOB as u128 * blob_hashes_len as u128
                        + (base_fee * tx.gas_limit()) as u128
                        + priority_fee * tx.gas_limit() as u128,
                );

                println!(
                    "DEBUG: Required balance: {}, account balance: {}",
                    required_balance, account.balance
                );

                if account.balance < required_balance {
                    println!(
                        "DEBUG: Insufficient balance for EIP4844 transaction, verification failed"
                    );
                    return Ok(VerificationResult::Failed);
                }
            } else {
                println!("DEBUG: Processing standard transaction");

                let base_fee = inclusion_block_header.base_fee_per_gas.ok_or_else(|| {
                    println!("ERROR: Failed to get base fee from inclusion block header");
                    eyre!("Failed to get base fee from inclusion block header")
                })?;
                println!("DEBUG: Base fee: {}", base_fee);

                let priority_fee = tx.max_priority_fee_per_gas().ok_or_else(|| {
                    println!("ERROR: Failed to get priority fee from transaction");
                    eyre!("Failed to get priority fee from transaction")
                })?;
                println!("DEBUG: Priority fee: {}", priority_fee);

                let required_balance = U256::from(
                    (base_fee * tx.gas_limit()) as u128 + priority_fee * tx.gas_limit() as u128,
                );

                println!(
                    "DEBUG: Required balance: {}, account balance: {}",
                    required_balance, account.balance
                );

                if account.balance < required_balance {
                    println!("DEBUG: Insufficient balance for transaction, verification failed");
                    return Ok(VerificationResult::Failed);
                }
            }
        }

        println!("DEBUG: Starting transaction merkle proof verification");
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        assert!(
            preconf_req_a.tx_merkle_proof.len() == txs.len() + 1,
            "Merkle proof count mismatch: expected {} (txs + anchor), got {}",
            txs.len() + 1,
            preconf_req_a.tx_merkle_proof.len()
        ); // +1 for the anchor tx

        println!("DEBUG: Verifying {} merkle proofs", preconf_req_a.tx_merkle_proof.len());
        for (index, merkle_proof) in preconf_req_a.tx_merkle_proof.iter().enumerate() {
            println!(
                "DEBUG: Verifying merkle proof {}/{}",
                index + 1,
                preconf_req_a.tx_merkle_proof.len()
            );
            assert!(
                merkle_proof.root == inclusion_block_header.transactions_root,
                "Merkle proof root mismatch for proof {}: expected {:?}, got {:?}",
                index,
                inclusion_block_header.transactions_root,
                merkle_proof.root
            );

            let node_result = trie.verify_proof(
                merkle_proof.root,
                merkle_proof.key.as_slice(),
                merkle_proof.proof.clone(),
            );

            let node = match node_result {
                Ok(Some(n)) => {
                    println!("DEBUG: Successfully verified merkle proof {}", index);
                    n
                }
                Ok(None) => {
                    println!("ERROR: Merkle proof {} verification returned None", index);
                    return Err(eyre!("Merkle proof {} verification returned None", index));
                }
                Err(e) => {
                    println!("ERROR: Merkle proof {} verification failed: {:?}", index, e);
                    return Err(eyre!("Merkle proof {} verification failed: {:?}", index, e));
                }
            };

            let tx = TxEnvelope::decode_2718(&mut node.as_slice()).map_err(|e| {
                println!(
                    "ERROR: Failed to decode transaction from merkle proof {}: {:?}",
                    index, e
                );
                eyre!("Failed to decode transaction from merkle proof {}: {:?}", index, e)
            })?;
            println!("DEBUG: Successfully decoded transaction from merkle proof {}", index);

            if index == 0 {
                assert!(
                    tx.tx_hash() == preconf_req_a.anchor_tx.tx_hash(),
                    "Anchor transaction hash mismatch: expected {:?}, got {:?}",
                    preconf_req_a.anchor_tx.tx_hash(),
                    tx.tx_hash()
                );
                println!("DEBUG: Verified anchor transaction hash");
            } else {
                assert!(
                    tx.tx_hash() == txs[index - 1].tx_hash(),
                    "Transaction hash mismatch at index {}: expected {:?}, got {:?}",
                    index - 1,
                    txs[index - 1].tx_hash(),
                    tx.tx_hash()
                );
                println!("DEBUG: Verified transaction hash at index {}", index - 1);
            }
        }

        println!("DEBUG: Starting anchor/sponsorship tx verification");
        let anchor_tx = preconf_req_a.anchor_tx;

        let anchor_to = anchor_tx.to().ok_or_else(|| {
            println!("ERROR: Anchor tx has no to address");
            eyre!("Anchor tx has no to address")
        })?;
        println!("DEBUG: Anchor tx to address: {:?}", anchor_to);

        assert!(
            anchor_to == taiyi_core,
            "Anchor tx to address mismatch: expected {:?}, got {:?}",
            taiyi_core,
            anchor_to
        );
        println!("DEBUG: Verified anchor tx to address matches taiyi core");

        let sponsor_call =
            sponsorEthBatchCall::abi_decode(anchor_tx.input(), true).map_err(|e| {
                println!("ERROR: Failed to decode sponsor call: {:?}", e);
                eyre!("Failed to decode sponsor call: {:?}", e)
            })?;
        println!(
            "DEBUG: Successfully decoded sponsor call with {} recipients",
            sponsor_call.recipients.len()
        );

        let mut senders_found: HashSet<Address> = HashSet::new();
        println!("DEBUG: Checking sponsorship for {} transactions", txs.len());
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            for tx in txs.iter() {
                let tx_signer = tx.recover_signer().map_err(|e| {
                    println!("ERROR: Failed to recover signer from transaction: {:?}", e);
                    eyre!("Failed to recover signer from transaction: {:?}", e)
                })?;

                if recipient == &tx_signer {
                    println!("DEBUG: Found sponsorship for signer: {:?}", tx_signer);
                    senders_found.insert(tx_signer);
                    break;
                }
            }
        }

        let all_signers: HashSet<Address> = txs
            .iter()
            .map(|tx| match tx.recover_signer() {
                Ok(signer) => {
                    println!("DEBUG: Transaction signer: {:?}", signer);
                    signer
                }
                Err(e) => {
                    println!("ERROR: Failed to recover signer from transaction: {:?}", e);
                    panic!("Failed to recover signer from transaction: {:?}", e);
                }
            })
            .collect();

        println!(
            "DEBUG: Found {} sponsored signers out of {} unique signers",
            senders_found.len(),
            all_signers.len()
        );

        if senders_found.len() != all_signers.len() {
            println!("ERROR: Not all transaction signers are sponsored");
            return Err(eyre!(
                "Sponsorship verification failed: Found {} sponsored senders but expected {} unique transaction senders. Missing sponsorship for some transactions.",
                senders_found.len(),
                all_signers.len()
            ));
        }
        println!("DEBUG: All transaction signers are sponsored");
    } else {
        println!("DEBUG: Processing Type B preconf request");
        let preconf_req_b = serde_json::from_str::<PreconfTypeB>(&preconf).map_err(|e| {
            println!("ERROR: Failed to parse Type B preconf request: {}", e);
            eyre!("Invalid Type B preconf request JSON format: {}", e)
        })?;
        println!("DEBUG: Successfully parsed Type B preconf request");

        let tx = preconf_req_b.preconf.clone().transaction.ok_or_else(|| {
            println!("ERROR: Type B preconf request has no transaction");
            eyre!("Type B preconf request has no transaction")
        })?;
        println!("DEBUG: Successfully extracted transaction from Type B request");

        let chain_id = tx.chain_id().ok_or_else(|| {
            println!("ERROR: Failed to get chain ID from transaction");
            eyre!("Transaction missing chain ID")
        })?;
        println!("DEBUG: Chain ID from transaction: {}", chain_id);

        let recovered_address = preconf_signature
            .recover_address_from_prehash(&preconf_req_b.preconf.digest(chain_id))
            .map_err(|e| {
                println!("ERROR: Failed to recover address from signature: {:?}", e);
                eyre!("Failed to recover address from preconf signature: {:?}", e)
            })?;
        println!("DEBUG: Successfully recovered address from signature: {:?}", recovered_address);

        assert!(
            underwriter_address == recovered_address,
            "Underwriter address mismatch: expected {:?}, got {:?}",
            underwriter_address,
            recovered_address
        );

        println!(
            "DEBUG: Verifying target slot: expected {}, actual {}",
            preconf_req_b.preconf.allocation.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );
        assert_eq!(
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp),
            preconf_req_b.preconf.allocation.target_slot,
            "Target slot mismatch: expected {}, got {}",
            preconf_req_b.preconf.allocation.target_slot,
            get_slot_from_timestamp(inclusion_block_header.timestamp, genesis_timestamp)
        );

        println!("DEBUG: Starting account verification for transaction");
        let account_merkle_proof = preconf_req_b.account_merkle_proof.clone();
        let account_key = account_merkle_proof.address;

        let tx_signer = tx.recover_signer().map_err(|e| {
            println!("ERROR: Failed to recover signer from transaction: {:?}", e);
            eyre!("Failed to recover signer from transaction: {:?}", e)
        })?;
        println!("DEBUG: Successfully recovered signer from transaction: {:?}", tx_signer);

        assert_eq!(
            account_key, tx_signer,
            "Account key mismatch: expected {:?}, got {:?}",
            account_key, tx_signer
        );

        let account = TrieAccount {
            nonce: account_merkle_proof.nonce,
            balance: account_merkle_proof.balance,
            storage_root: account_merkle_proof.storage_hash,
            code_hash: account_merkle_proof.code_hash,
        };
        println!("DEBUG: Account state - nonce: {}, balance: {}", account.nonce, account.balance);

        verify_proof(
            previous_block_header.state_root,
            Nibbles::unpack(keccak256(account_key)),
            Some(alloy_rlp::encode(account)),
            &account_merkle_proof.account_proof,
        )
        .map_err(|e| {
            println!("ERROR: Account state verification failed: {:?}", e);
            eyre!("Account state verification failed: {:?}", e)
        })?;
        println!("DEBUG: Account state verification successful");

        if account.nonce > tx.nonce() {
            println!(
                "DEBUG: Account nonce ({}) > tx nonce ({}), verification failed",
                account.nonce,
                tx.nonce()
            );
            return Ok(VerificationResult::Failed);
        }

        if tx.is_eip4844() {
            println!("DEBUG: Processing EIP4844 transaction");
            let tx_eip4844 = tx.as_eip4844().ok_or_else(|| {
                println!("ERROR: Failed to parse EIP4844 transaction");
                eyre!("Transaction identified as EIP4844 but failed to parse as such")
            })?;
            println!("DEBUG: Successfully parsed EIP4844 transaction");

            let blob_fee =
                inclusion_block_header.blob_fee(BlobParams::prague()).ok_or_else(|| {
                    println!("ERROR: Failed to get blob fee from inclusion block header");
                    eyre!("Failed to get blob fee from inclusion block header")
                })?;
            println!("DEBUG: Blob fee: {}", blob_fee);

            let blob_hashes_len = tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len();
            println!("DEBUG: Transaction has {} blob hashes", blob_hashes_len);

            let base_fee = inclusion_block_header.base_fee_per_gas.ok_or_else(|| {
                println!("ERROR: Failed to get base fee from inclusion block header");
                eyre!("Failed to get base fee from inclusion block header")
            })?;
            println!("DEBUG: Base fee: {}", base_fee);

            let priority_fee = tx.max_priority_fee_per_gas().ok_or_else(|| {
                println!("ERROR: Failed to get priority fee from transaction");
                eyre!("Failed to get priority fee from transaction")
            })?;
            println!("DEBUG: Priority fee: {}", priority_fee);

            let required_balance = U256::from(
                blob_fee * DATA_GAS_PER_BLOB as u128 * blob_hashes_len as u128
                    + (base_fee * tx.gas_limit()) as u128
                    + priority_fee * tx.gas_limit() as u128,
            );

            println!(
                "DEBUG: Required balance: {}, account balance: {}",
                required_balance, account.balance
            );

            if account.balance < required_balance {
                println!(
                    "DEBUG: Insufficient balance for EIP4844 transaction, verification failed"
                );
                return Ok(VerificationResult::Failed);
            }
        } else {
            println!("DEBUG: Processing standard transaction");

            let base_fee = inclusion_block_header.base_fee_per_gas.ok_or_else(|| {
                println!("ERROR: Failed to get base fee from inclusion block header");
                eyre!("Failed to get base fee from inclusion block header")
            })?;
            println!("DEBUG: Base fee: {}", base_fee);

            let priority_fee = tx.max_priority_fee_per_gas().ok_or_else(|| {
                println!("ERROR: Failed to get priority fee from transaction");
                eyre!("Failed to get priority fee from transaction")
            })?;
            println!("DEBUG: Priority fee: {}", priority_fee);

            let required_balance = U256::from(
                (base_fee * tx.gas_limit()) as u128 + priority_fee * tx.gas_limit() as u128,
            );

            println!(
                "DEBUG: Required balance: {}, account balance: {}",
                required_balance, account.balance
            );

            if account.balance < required_balance {
                println!("DEBUG: Insufficient balance for transaction, verification failed");
                return Ok(VerificationResult::Failed);
            }
        }

        println!("DEBUG: Starting transaction merkle proof verification");
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        assert!(
            preconf_req_b.tx_merkle_proof.len() == 2,
            "Merkle proof count mismatch: expected 2 (user tx + sponsorship), got {}",
            preconf_req_b.tx_merkle_proof.len()
        );

        println!("DEBUG: Verifying {} merkle proofs", preconf_req_b.tx_merkle_proof.len());
        for (index, merkle_proof) in preconf_req_b.tx_merkle_proof.iter().enumerate() {
            println!(
                "DEBUG: Verifying merkle proof {}/{}",
                index + 1,
                preconf_req_b.tx_merkle_proof.len()
            );
            assert!(
                merkle_proof.root == inclusion_block_header.transactions_root,
                "Merkle proof root mismatch for proof {}: expected {:?}, got {:?}",
                index,
                inclusion_block_header.transactions_root,
                merkle_proof.root
            );

            let node_result = trie.verify_proof(
                merkle_proof.root,
                merkle_proof.key.as_slice(),
                merkle_proof.proof.clone(),
            );

            let node = match node_result {
                Ok(Some(n)) => {
                    println!("DEBUG: Successfully verified merkle proof {}", index);
                    n
                }
                Ok(None) => {
                    println!("ERROR: Merkle proof {} verification returned None", index);
                    return Err(eyre!("Merkle proof {} verification returned None", index));
                }
                Err(e) => {
                    println!("ERROR: Merkle proof {} verification failed: {:?}", index, e);
                    return Err(eyre!("Merkle proof {} verification failed: {:?}", index, e));
                }
            };

            let decoded_tx = TxEnvelope::decode_2718(&mut node.as_slice()).map_err(|e| {
                println!(
                    "ERROR: Failed to decode transaction from merkle proof {}: {:?}",
                    index, e
                );
                eyre!("Failed to decode transaction from merkle proof {}: {:?}", index, e)
            })?;
            println!("DEBUG: Successfully decoded transaction from merkle proof {}", index);

            if index == 0 {
                assert!(
                    decoded_tx.tx_hash() == tx.tx_hash(),
                    "User transaction hash mismatch: expected {:?}, got {:?}",
                    tx.tx_hash(),
                    decoded_tx.tx_hash()
                );
                println!("DEBUG: Verified user transaction hash");
            } else {
                assert!(
                    decoded_tx.tx_hash() == preconf_req_b.sponsorship_tx.tx_hash(),
                    "Sponsorship transaction hash mismatch: expected {:?}, got {:?}",
                    preconf_req_b.sponsorship_tx.tx_hash(),
                    decoded_tx.tx_hash()
                );
                println!("DEBUG: Verified sponsorship transaction hash");
            }
        }

        println!("DEBUG: Starting sponsorship tx verification");
        let sponsorship_tx = preconf_req_b.sponsorship_tx;

        let sponsorship_to = sponsorship_tx.to().ok_or_else(|| {
            println!("ERROR: Sponsorship tx has no to address");
            eyre!("Sponsorship tx has no to address")
        })?;
        println!("DEBUG: Sponsorship tx to address: {:?}", sponsorship_to);

        assert!(
            sponsorship_to == taiyi_core,
            "Sponsorship tx to address mismatch: expected {:?}, got {:?}",
            taiyi_core,
            sponsorship_to
        ); // taiyi core address
        println!("DEBUG: Verified sponsorship tx to address matches taiyi core");

        let sponsor_call =
            sponsorEthBatchCall::abi_decode(sponsorship_tx.input(), true).map_err(|e| {
                println!("ERROR: Failed to decode sponsor call: {:?}", e);
                eyre!("Failed to decode sponsor call: {:?}", e)
            })?;
        println!(
            "DEBUG: Successfully decoded sponsor call with {} recipients",
            sponsor_call.recipients.len()
        );

        let mut sender_found = false;
        println!("DEBUG: Checking sponsorship for transaction signer");
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            let tx_signer = tx.recover_signer().map_err(|e| {
                println!("ERROR: Failed to recover signer from transaction: {:?}", e);
                eyre!("Failed to recover signer from transaction: {:?}", e)
            })?;

            if recipient == &tx_signer {
                println!("DEBUG: Found sponsorship for signer: {:?}", tx_signer);
                sender_found = true;
                break;
            }
        }

        if !sender_found {
            println!("ERROR: No sponsorship found for transaction signer");
            return Err(eyre!("Sponsorship verification failed: No sponsorship tx for sender"));
        }
        println!("DEBUG: Transaction signer is sponsored");
    }

    println!("DEBUG: Verification completed successfully");
    Ok(VerificationResult::Success)
}

pub fn main() {
    println!("DEBUG: Starting poi verification");

    let preconf = sp1_zkvm::io::read::<String>(); // preconfirmation request encoded as serde string
    let preconf_signature_str = sp1_zkvm::io::read::<String>(); // hex-encoded preconfirmation signature
    let is_type_a = sp1_zkvm::io::read::<bool>(); // true if the preconf req is of type A, false otherwise
    let inclusion_block_header_str = sp1_zkvm::io::read::<String>(); // block header of the inclusion block encoded as serde string
    let inclusion_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the inclusion block
    let previous_block_header_str = sp1_zkvm::io::read::<String>(); // block header of the previous block encoded as serde string
    let previous_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the previous block
    let underwriter_address = sp1_zkvm::io::read::<Address>(); // address of the underwriter
    let genesis_timestamp = sp1_zkvm::io::read::<u64>(); // genesis timestamp
    let taiyi_core = sp1_zkvm::io::read::<Address>(); // taiyi core address

    println!(
        "DEBUG: Processing {} request for underwriter: {:?}",
        if is_type_a { "Type A" } else { "Type B" },
        underwriter_address
    );
    println!("DEBUG: Inclusion block hash: {:?}", inclusion_block_hash);

    let inclusion_block_header = match serde_json::from_str::<Header>(&inclusion_block_header_str) {
        Ok(header) => {
            println!(
                "DEBUG: Successfully parsed inclusion block header, number: {}",
                header.number
            );
            header
        }
        Err(e) => {
            println!("ERROR: Failed to parse inclusion block header: {}", e);
            panic!("Invalid inclusion block header JSON format: {}", e);
        }
    };

    let preconf_signature = match PrimitiveSignature::from_str(&preconf_signature_str) {
        Ok(sig) => {
            println!("DEBUG: Successfully parsed preconf signature");
            sig
        }
        Err(e) => {
            println!("ERROR: Failed to parse preconf signature: {}", e);
            panic!("Invalid preconf signature format: {}", e);
        }
    };

    let public_values = create_public_values(
        &inclusion_block_header,
        inclusion_block_hash,
        underwriter_address,
        &preconf_signature,
        genesis_timestamp,
        taiyi_core,
    );

    match run_poi_verification(
        preconf,
        preconf_signature_str,
        is_type_a,
        inclusion_block_header_str,
        inclusion_block_hash,
        previous_block_header_str,
        previous_block_hash,
        underwriter_address,
        genesis_timestamp,
        taiyi_core,
    ) {
        Ok(result) => {
            match result {
                VerificationResult::Success => {
                    println!("DEBUG: Verification successful, committing public values");
                }
                VerificationResult::Failed => {
                    println!("DEBUG: Verification failed but this is a valid outcome, committing public values");
                }
            }
            let bytes = public_values.abi_encode_sequence();
            sp1_zkvm::io::commit_slice(&bytes);
        }
        Err(e) => {
            println!("ERROR: Verification error: {}", e);
            panic!("Verification error: {}", e);
        }
    }

    println!("DEBUG: Poi verification completed");
}
