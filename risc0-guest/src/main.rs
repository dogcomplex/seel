// risc0-guest/src/main.rs
// This program runs inside the risc0 zkVM

#![no_main]
#![no_std] // std support is experimental, stick to no_std for guest

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;

// Register the entry point
risc0_zkvm::guest::entry!(main);

fn main() {
    // Read the private inputs passed by the host
    // Host should send them sequentially as UTF-8 byte slices

    // 1. Read model hash bytes
    let model_hash_bytes: Vec<u8> = env::read();
    // 2. Read constraint hash bytes
    let constraint_hash_bytes: Vec<u8> = env::read();
    // 3. Read prompt hash bytes
    let prompt_hash_bytes: Vec<u8> = env::read();
    // 4. Read output hash bytes
    let output_hash_bytes: Vec<u8> = env::read();

    // **Core "Logic"**: Commit the received inputs to the public journal.
    // This proves that *this specific guest code* received these exact inputs.
    env::commit_slice(&model_hash_bytes);
    env::commit_slice(&constraint_hash_bytes);
    env::commit_slice(&prompt_hash_bytes);
    env::commit_slice(&output_hash_bytes);
} 