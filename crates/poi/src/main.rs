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
use taiyi_zkvm_types::{types::*, utils::*};

sp1_zkvm::entrypoint!(main);

pub fn get_slot_from_timestamp(timestamp: u64, genesis_timestamp: u64) -> u64 {
    (timestamp - genesis_timestamp) / SLOT_DURATION_SECS
}

pub fn main() {
    println!("DEBUG: Starting poi verification");

    // Read an input to the program.
    let preconf = sp1_zkvm::io::read::<String>(); // preconfirmation request encoded as serde string
    let preconf_signature = sp1_zkvm::io::read::<String>(); // hex-encoded preconfirmation signature
    let is_type_a = sp1_zkvm::io::read::<bool>(); // true if the preconf req is of type A, false otherwise
    let inclusion_block_header = sp1_zkvm::io::read::<String>(); // block header of the inclusion block encoded as serde string
    let inclusion_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the inclusion block
    let previous_block_header = sp1_zkvm::io::read::<String>(); // block header of the previous block encoded as serde string
    let previous_block_hash = sp1_zkvm::io::read::<B256>(); // hash of the previous block
    let underwriter_address = sp1_zkvm::io::read::<Address>(); // address of the underwriter
    let genesis_timestamp = sp1_zkvm::io::read::<u64>(); // genesis timestamp
    let taiyi_core = sp1_zkvm::io::read::<Address>(); // taiyi core address

    println!(
        "DEBUG: Processing {} request for underwriter: {:?}",
        if is_type_a { "Type A" } else { "Type B" },
        underwriter_address
    );
    println!(
        "DEBUG: Inclusion block hash: {:?}, number: {}",
        inclusion_block_hash,
        serde_json::from_str::<Header>(&inclusion_block_header)
            .map(|h| h.number)
            .unwrap_or_default()
    );

    let inclusion_block_header = match serde_json::from_str::<Header>(&inclusion_block_header) {
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

    let previous_block_header = match serde_json::from_str::<Header>(&previous_block_header) {
        Ok(header) => {
            println!("DEBUG: Successfully parsed previous block header, number: {}", header.number);
            header
        }
        Err(e) => {
            println!("ERROR: Failed to parse previous block header: {}", e);
            panic!("Invalid previous block header JSON format: {}", e);
        }
    };

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

    let preconf_signature = match PrimitiveSignature::from_str(&preconf_signature) {
        Ok(sig) => {
            println!("DEBUG: Successfully parsed preconf signature");
            sig
        }
        Err(e) => {
            println!("ERROR: Failed to parse preconf signature: {}", e);
            panic!("Invalid preconf signature format: {}", e);
        }
    };

    if is_type_a {
        println!("DEBUG: Processing Type A preconf request");
        let preconf_req_a = match serde_json::from_str::<PreconfTypeA>(&preconf) {
            Ok(req) => {
                println!("DEBUG: Successfully parsed Type A preconf request");
                req
            }
            Err(e) => {
                println!("ERROR: Failed to parse Type A preconf request: {}", e);
                panic!("Invalid Type A preconf request JSON format: {}", e);
            }
        };
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
                    panic!("Transaction missing chain ID");
                }
            },
            None => {
                println!("ERROR: No transactions in Type A request");
                panic!("Type A request contains no transactions");
            }
        };

        // Check that the underwriter address matches the preconf req type a signer
        let recovered_address = match preconf_signature
            .recover_address_from_prehash(&preconf_req_a.preconf.digest(chain_id))
        {
            Ok(addr) => {
                println!("DEBUG: Successfully recovered address from signature: {:?}", addr);
                addr
            }
            Err(e) => {
                println!("ERROR: Failed to recover address from signature: {:?}", e);
                panic!("Failed to recover address from preconf signature: {:?}", e);
            }
        };

        assert!(
            underwriter_address == recovered_address,
            "Underwriter address mismatch: expected {:?}, got {:?}",
            underwriter_address,
            recovered_address
        );

        // Encode the public values of the program.
        let bytes = (
            inclusion_block_header.timestamp,
            inclusion_block_hash,
            inclusion_block_header.number,
            underwriter_address,
            preconf_signature.as_bytes().to_vec(),
            genesis_timestamp,
            taiyi_core,
        )
            .abi_encode_sequence();

        // Target slot verification
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

        // Account verification
        println!("DEBUG: Starting account verification for {} transactions", txs.len());
        for (index, tx) in txs.iter().enumerate() {
            println!("DEBUG: Verifying account for transaction {}/{}", index + 1, txs.len());
            let account_merkle_proof = preconf_req_a.account_merkle_proof[index].clone();
            let account_key = account_merkle_proof.address;

            // Check that the account in proof matches the signer of the transaction
            let tx_signer = match tx.recover_signer() {
                Ok(signer) => {
                    println!("DEBUG: Successfully recovered signer from transaction: {:?}", signer);
                    signer
                }
                Err(e) => {
                    println!("ERROR: Failed to recover signer from transaction {}: {:?}", index, e);
                    panic!("Failed to recover signer from transaction {}: {:?}", index, e);
                }
            };

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

            // Verify the account state
            match verify_proof(
                previous_block_header.state_root,
                Nibbles::unpack(keccak256(account_key)),
                Some(alloy_rlp::encode(account)),
                &account_merkle_proof.account_proof,
            ) {
                Ok(_) => println!("DEBUG: Account state verification successful for tx {}", index),
                Err(e) => {
                    println!("ERROR: Account state verification failed for tx {}: {:?}", index, e);
                    panic!("Account state verification failed for tx {}: {:?}", index, e);
                }
            };

            if account.nonce > tx.nonce() {
                println!(
                    "DEBUG: Account nonce ({}) > tx nonce ({}), verification failed",
                    account.nonce,
                    tx.nonce()
                );
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return;
            }

            if tx.is_eip4844() {
                println!("DEBUG: Processing EIP4844 transaction");
                let tx_eip4844 = match tx.as_eip4844() {
                    Some(tx) => {
                        println!("DEBUG: Successfully parsed EIP4844 transaction");
                        tx
                    }
                    None => {
                        println!("ERROR: Failed to parse EIP4844 transaction");
                        panic!("Transaction identified as EIP4844 but failed to parse as such");
                    }
                };

                let blob_fee = match inclusion_block_header.blob_fee(BlobParams::prague()) {
                    Some(fee) => {
                        println!("DEBUG: Blob fee: {}", fee);
                        fee
                    }
                    None => {
                        println!("ERROR: Failed to get blob fee from inclusion block header");
                        panic!("Failed to get blob fee from inclusion block header");
                    }
                };

                let blob_hashes_len =
                    tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len();
                println!("DEBUG: Transaction has {} blob hashes", blob_hashes_len);

                let base_fee = match inclusion_block_header.base_fee_per_gas {
                    Some(fee) => {
                        println!("DEBUG: Base fee: {}", fee);
                        fee
                    }
                    None => {
                        println!("ERROR: Failed to get base fee from inclusion block header");
                        panic!("Failed to get base fee from inclusion block header");
                    }
                };

                let priority_fee = match tx.max_priority_fee_per_gas() {
                    Some(fee) => {
                        println!("DEBUG: Priority fee: {}", fee);
                        fee
                    }
                    None => {
                        println!("ERROR: Failed to get priority fee from transaction");
                        panic!("Failed to get priority fee from transaction");
                    }
                };

                let required_balance = U256::from(
                    blob_fee * DATA_GAS_PER_BLOB as u128 * blob_hashes_len as u128
                        + (base_fee * tx.gas_limit()) as u128
                        + priority_fee * tx.gas_limit() as u128,
                );

                println!(
                    "DEBUG: Required balance: {}, account balance: {}",
                    required_balance, account.balance
                );

                // Check balance
                if account.balance < required_balance {
                    println!(
                        "DEBUG: Insufficient balance for EIP4844 transaction, verification failed"
                    );
                    // Commit the public values of the program.
                    sp1_zkvm::io::commit_slice(&bytes);
                    return;
                }
            } else {
                println!("DEBUG: Processing standard transaction");

                let base_fee = match inclusion_block_header.base_fee_per_gas {
                    Some(fee) => {
                        println!("DEBUG: Base fee: {}", fee);
                        fee
                    }
                    None => {
                        println!("ERROR: Failed to get base fee from inclusion block header");
                        panic!("Failed to get base fee from inclusion block header");
                    }
                };

                let priority_fee = match tx.max_priority_fee_per_gas() {
                    Some(fee) => {
                        println!("DEBUG: Priority fee: {}", fee);
                        fee
                    }
                    None => {
                        println!("ERROR: Failed to get priority fee from transaction");
                        panic!("Failed to get priority fee from transaction");
                    }
                };

                let required_balance = U256::from(
                    (base_fee * tx.gas_limit()) as u128 + priority_fee * tx.gas_limit() as u128,
                );

                println!(
                    "DEBUG: Required balance: {}, account balance: {}",
                    required_balance, account.balance
                );

                // Check balance
                if account.balance < required_balance {
                    println!("DEBUG: Insufficient balance for transaction, verification failed");
                    // Commit the public values of the program.
                    sp1_zkvm::io::commit_slice(&bytes);
                    return;
                }
            }
        }

        // User transactions and anchor tx inclusion
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

            // Verify the merkle proof
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
                    panic!("Merkle proof {} verification returned None", index);
                }
                Err(e) => {
                    println!("ERROR: Merkle proof {} verification failed: {:?}", index, e);
                    panic!("Merkle proof {} verification failed: {:?}", index, e);
                }
            };

            // Decode the transaction
            let tx = match TxEnvelope::decode_2718(&mut node.as_slice()) {
                Ok(tx) => {
                    println!("DEBUG: Successfully decoded transaction from merkle proof {}", index);
                    tx
                }
                Err(e) => {
                    println!(
                        "ERROR: Failed to decode transaction from merkle proof {}: {:?}",
                        index, e
                    );
                    panic!("Failed to decode transaction from merkle proof {}: {:?}", index, e);
                }
            };

            if index == 0 {
                // check that the first transaction is the anchor tx
                assert!(
                    tx.tx_hash() == preconf_req_a.anchor_tx.tx_hash(),
                    "Anchor transaction hash mismatch: expected {:?}, got {:?}",
                    preconf_req_a.anchor_tx.tx_hash(),
                    tx.tx_hash()
                );
                println!("DEBUG: Verified anchor transaction hash");
            } else {
                // check that the transactions are in the correct order
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

        // Anchor/sponsorship tx verification (correct smart contract call and data passed)
        println!("DEBUG: Starting anchor/sponsorship tx verification");
        let anchor_tx = preconf_req_a.anchor_tx;

        // Check that the anchor tx to field matches the taiyi core address
        let anchor_to = match anchor_tx.to() {
            Some(to) => {
                println!("DEBUG: Anchor tx to address: {:?}", to);
                to
            }
            None => {
                println!("ERROR: Anchor tx has no to address");
                panic!("Anchor tx has no to address");
            }
        };

        assert!(
            anchor_to == taiyi_core,
            "Anchor tx to address mismatch: expected {:?}, got {:?}",
            taiyi_core,
            anchor_to
        );
        println!("DEBUG: Verified anchor tx to address matches taiyi core");

        // Decode the sponsor call
        let sponsor_call = match sponsorEthBatchCall::abi_decode(anchor_tx.input(), true) {
            Ok(call) => {
                println!(
                    "DEBUG: Successfully decoded sponsor call with {} recipients",
                    call.recipients.len()
                );
                call
            }
            Err(e) => {
                println!("ERROR: Failed to decode sponsor call: {:?}", e);
                panic!("Failed to decode sponsor call: {:?}", e);
            }
        };

        let mut senders_found: HashSet<Address> = HashSet::new();
        println!("DEBUG: Checking sponsorship for {} transactions", txs.len());
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            for tx in txs.iter() {
                let tx_signer = match tx.recover_signer() {
                    Ok(signer) => signer,
                    Err(e) => {
                        println!("ERROR: Failed to recover signer from transaction: {:?}", e);
                        panic!("Failed to recover signer from transaction: {:?}", e);
                    }
                };

                if recipient == &tx_signer {
                    // TODO: check amount
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
            panic!(
                "Sponsorship verification failed: Found {} sponsored senders but expected {} unique transaction senders. Missing sponsorship for some transactions.",
                senders_found.len(),
                all_signers.len()
            );
        }
        println!("DEBUG: All transaction signers are sponsored");
    } else {
        println!("DEBUG: Processing Type B preconf request");
        let preconf_req_b = match serde_json::from_str::<PreconfTypeB>(&preconf) {
            Ok(req) => {
                println!("DEBUG: Successfully parsed Type B preconf request");
                req
            }
            Err(e) => {
                println!("ERROR: Failed to parse Type B preconf request: {}", e);
                panic!("Invalid Type B preconf request JSON format: {}", e);
            }
        };

        let tx = match preconf_req_b.preconf.clone().transaction {
            Some(tx) => {
                println!("DEBUG: Successfully extracted transaction from Type B request");
                tx
            }
            None => {
                println!("ERROR: Type B preconf request has no transaction");
                panic!("Type B preconf request has no transaction");
            }
        };

        let chain_id = match tx.chain_id() {
            Some(id) => {
                println!("DEBUG: Chain ID from transaction: {}", id);
                id
            }
            None => {
                println!("ERROR: Failed to get chain ID from transaction");
                panic!("Transaction missing chain ID");
            }
        };

        // Check that the underwriter address matches the preconf req type b signer
        let recovered_address = match preconf_signature
            .recover_address_from_prehash(&preconf_req_b.preconf.digest(chain_id))
        {
            Ok(addr) => {
                println!("DEBUG: Successfully recovered address from signature: {:?}", addr);
                addr
            }
            Err(e) => {
                println!("ERROR: Failed to recover address from signature: {:?}", e);
                panic!("Failed to recover address from preconf signature: {:?}", e);
            }
        };

        assert!(
            underwriter_address == recovered_address,
            "Underwriter address mismatch: expected {:?}, got {:?}",
            underwriter_address,
            recovered_address
        );

        // Encode the public values of the program.
        let bytes = (
            inclusion_block_header.timestamp,
            inclusion_block_hash,
            inclusion_block_header.number,
            underwriter_address,
            preconf_signature.as_bytes().to_vec(),
            genesis_timestamp,
            taiyi_core,
        )
            .abi_encode_sequence();

        // Target slot verification
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

        // Account verification
        println!("DEBUG: Starting account verification for Type B request");
        let account_merkle_proof = preconf_req_b.account_merkle_proof.clone();
        let account_key = account_merkle_proof.address;

        // Check that the account in proof matches the signer of the transaction
        let tx_signer = match tx.recover_signer() {
            Ok(signer) => {
                println!("DEBUG: Successfully recovered signer from transaction: {:?}", signer);
                signer
            }
            Err(e) => {
                println!("ERROR: Failed to recover signer from transaction: {:?}", e);
                panic!("Failed to recover signer from transaction: {:?}", e);
            }
        };

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

        // Verify the account state
        match verify_proof(
            previous_block_header.state_root,
            Nibbles::unpack(keccak256(account_key)),
            Some(alloy_rlp::encode(account)),
            &account_merkle_proof.account_proof,
        ) {
            Ok(_) => println!("DEBUG: Account state verification successful"),
            Err(e) => {
                println!("ERROR: Account state verification failed: {:?}", e);
                panic!("Account state verification failed: {:?}", e);
            }
        };

        if account.nonce > tx.nonce() {
            println!(
                "DEBUG: Account nonce ({}) > tx nonce ({}), verification failed",
                account.nonce,
                tx.nonce()
            );
            // Commit the public values of the program.
            sp1_zkvm::io::commit_slice(&bytes);
            return;
        }

        if tx.is_eip4844() {
            println!("DEBUG: Processing EIP4844 transaction");
            let tx_eip4844 = match tx.as_eip4844() {
                Some(tx) => {
                    println!("DEBUG: Successfully parsed EIP4844 transaction");
                    tx
                }
                None => {
                    println!("ERROR: Failed to parse EIP4844 transaction");
                    panic!("Transaction identified as EIP4844 but failed to parse as such");
                }
            };

            let blob_fee = match inclusion_block_header.blob_fee(BlobParams::prague()) {
                Some(fee) => {
                    println!("DEBUG: Blob fee: {}", fee);
                    fee
                }
                None => {
                    println!("ERROR: Failed to get blob fee from inclusion block header");
                    panic!("Failed to get blob fee from inclusion block header");
                }
            };

            let blob_hashes_len = tx_eip4844.tx().blob_versioned_hashes().unwrap_or_default().len();
            println!("DEBUG: Transaction has {} blob hashes", blob_hashes_len);

            let base_fee = match inclusion_block_header.base_fee_per_gas {
                Some(fee) => {
                    println!("DEBUG: Base fee: {}", fee);
                    fee
                }
                None => {
                    println!("ERROR: Failed to get base fee from inclusion block header");
                    panic!("Failed to get base fee from inclusion block header");
                }
            };

            let priority_fee = match tx.max_priority_fee_per_gas() {
                Some(fee) => {
                    println!("DEBUG: Priority fee: {}", fee);
                    fee
                }
                None => {
                    println!("ERROR: Failed to get priority fee from transaction");
                    panic!("Failed to get priority fee from transaction");
                }
            };

            let required_balance = U256::from(
                blob_fee * DATA_GAS_PER_BLOB as u128 * blob_hashes_len as u128
                    + (base_fee * tx.gas_limit()) as u128
                    + priority_fee * tx.gas_limit() as u128,
            );

            println!(
                "DEBUG: Required balance: {}, account balance: {}",
                required_balance, account.balance
            );

            // Check balance
            if account.balance < required_balance {
                println!(
                    "DEBUG: Insufficient balance for EIP4844 transaction, verification failed"
                );
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return;
            }
        } else {
            println!("DEBUG: Processing standard transaction");

            let base_fee = match inclusion_block_header.base_fee_per_gas {
                Some(fee) => {
                    println!("DEBUG: Base fee: {}", fee);
                    fee
                }
                None => {
                    println!("ERROR: Failed to get base fee from inclusion block header");
                    panic!("Failed to get base fee from inclusion block header");
                }
            };

            let priority_fee = match tx.max_priority_fee_per_gas() {
                Some(fee) => {
                    println!("DEBUG: Priority fee: {}", fee);
                    fee
                }
                None => {
                    println!("ERROR: Failed to get priority fee from transaction");
                    panic!("Failed to get priority fee from transaction");
                }
            };

            let required_balance = U256::from(
                (base_fee * tx.gas_limit()) as u128 + priority_fee * tx.gas_limit() as u128,
            );

            println!(
                "DEBUG: Required balance: {}, account balance: {}",
                required_balance, account.balance
            );

            // Check balance
            if account.balance < required_balance {
                println!("DEBUG: Insufficient balance for transaction, verification failed");
                // Commit the public values of the program.
                sp1_zkvm::io::commit_slice(&bytes);
                return;
            }
        }

        // User transaction and sponsorship tx inclusion
        // Only verify the user tx and the sponsorship tx
        println!("DEBUG: Starting transaction merkle proof verification for Type B");
        assert!(
            preconf_req_b.tx_merkle_proof.len() == 2,
            "Expected 2 merkle proofs (user tx and sponsorship tx), got {}",
            preconf_req_b.tx_merkle_proof.len()
        );

        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        println!("DEBUG: Verifying {} merkle proofs", preconf_req_b.tx_merkle_proof.len());
        for (index, merkle_proof) in preconf_req_b.tx_merkle_proof.iter().enumerate() {
            println!("DEBUG: Verifying merkle proof {}/2", index + 1);
            assert!(
                merkle_proof.root == inclusion_block_header.transactions_root,
                "Merkle proof root mismatch for proof {}: expected {:?}, got {:?}",
                index,
                inclusion_block_header.transactions_root,
                merkle_proof.root
            );

            // Verify the merkle proof
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
                    panic!("Merkle proof {} verification returned None", index);
                }
                Err(e) => {
                    println!("ERROR: Merkle proof {} verification failed: {:?}", index, e);
                    panic!("Merkle proof {} verification failed: {:?}", index, e);
                }
            };

            // Decode the transaction
            let decoded_tx = match TxEnvelope::decode_2718(&mut node.as_slice()) {
                Ok(tx) => {
                    println!("DEBUG: Successfully decoded transaction from merkle proof {}", index);
                    tx
                }
                Err(e) => {
                    println!(
                        "ERROR: Failed to decode transaction from merkle proof {}: {:?}",
                        index, e
                    );
                    panic!("Failed to decode transaction from merkle proof {}: {:?}", index, e);
                }
            };

            if index == 0 {
                // check that the user tx is the first transaction
                assert!(
                    decoded_tx.tx_hash() == tx.tx_hash(),
                    "User transaction hash mismatch: expected {:?}, got {:?}",
                    tx.tx_hash(),
                    decoded_tx.tx_hash()
                );
                println!("DEBUG: Verified user transaction hash");
            } else {
                // check that the sponsorship tx is the second transaction
                assert!(
                    decoded_tx.tx_hash() == preconf_req_b.sponsorship_tx.tx_hash(),
                    "Sponsorship transaction hash mismatch: expected {:?}, got {:?}",
                    preconf_req_b.sponsorship_tx.tx_hash(),
                    decoded_tx.tx_hash()
                );
                println!("DEBUG: Verified sponsorship transaction hash");
            }
        }

        // Sponsorship tx verification (correct smart contract call and data passed)
        println!("DEBUG: Starting sponsorship tx verification");
        let sponsorship_tx = preconf_req_b.sponsorship_tx;

        // Check that the sponsorship tx to field matches the taiyi core address
        let sponsorship_to = match sponsorship_tx.to() {
            Some(to) => {
                println!("DEBUG: Sponsorship tx to address: {:?}", to);
                to
            }
            None => {
                println!("ERROR: Sponsorship tx has no to address");
                panic!("Sponsorship tx has no to address");
            }
        };

        // TODO: Check if this is correct (aka. should the sponsorship tx be to the taiyi core address?)
        assert!(
            sponsorship_to == taiyi_core,
            "Sponsorship tx to address mismatch: expected {:?}, got {:?}",
            taiyi_core,
            sponsorship_to
        ); // taiyi core address
        println!("DEBUG: Verified sponsorship tx to address matches taiyi core");

        // Decode the sponsor call
        let sponsor_call = match sponsorEthBatchCall::abi_decode(sponsorship_tx.input(), true) {
            Ok(call) => {
                println!(
                    "DEBUG: Successfully decoded sponsor call with {} recipients",
                    call.recipients.len()
                );
                call
            }
            Err(e) => {
                println!("ERROR: Failed to decode sponsor call: {:?}", e);
                panic!("Failed to decode sponsor call: {:?}", e);
            }
        };

        let mut sender_found = false;
        println!("DEBUG: Checking sponsorship for transaction signer");
        for (recipient, _amount) in sponsor_call.recipients.iter().zip(sponsor_call.amounts.iter())
        {
            let tx_signer = match tx.recover_signer() {
                Ok(signer) => {
                    println!("DEBUG: Transaction signer: {:?}", signer);
                    signer
                }
                Err(e) => {
                    println!("ERROR: Failed to recover signer from transaction: {:?}", e);
                    panic!("Failed to recover signer from transaction: {:?}", e);
                }
            };

            if recipient == &tx_signer {
                // TODO: check amount
                println!("DEBUG: Found sponsorship for signer: {:?}", tx_signer);
                sender_found = true;
                break;
            }
        }

        if !sender_found {
            println!("ERROR: No sponsorship found for transaction signer");
            panic!("Sponsorship verification failed: No sponsorship tx for sender");
        }
        println!("DEBUG: Transaction signer is sponsored");
    }

    // Encode the public values of the program.
    println!("DEBUG: Encoding final public values");
    let bytes = PublicValuesStruct {
        proofBlockTimestamp: inclusion_block_header.timestamp,
        proofBlockHash: inclusion_block_hash,
        proofBlockNumber: inclusion_block_header.number,
        underwriterAddress: underwriter_address,
        proofSignature: preconf_signature.as_bytes().to_vec().into(),
        genesisTimestamp: genesis_timestamp,
        taiyiCore: taiyi_core,
    }
    .abi_encode_sequence();

    println!("DEBUG: Committing public values, verification successful");
    // Commit the public values of the program.
    sp1_zkvm::io::commit_slice(&bytes);

    println!("DEBUG: Poi verification completed successfully");
}
