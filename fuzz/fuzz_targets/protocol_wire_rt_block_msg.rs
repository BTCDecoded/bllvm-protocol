#![no_main]
//! Plan harness (generated).

use std::io::Cursor;
use std::sync::Arc;
use blvm_protocol::network::NetworkMessage;
use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::{deserialize_block_with_witnesses_pair, deserialize_message, serialize_message};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok((block, witnesses)) = deserialize_block_with_witnesses_pair(data) {
        let msg = NetworkMessage::Block(Arc::new(block), witnesses);
        if let Ok(w) = serialize_message(&msg, BITCOIN_MAGIC_MAINNET) {
            let _ = deserialize_message(&mut Cursor::new(&w), BITCOIN_MAGIC_MAINNET);
        }
    }
});
