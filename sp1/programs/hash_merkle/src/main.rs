#![no_main]
sp1_zkvm::entrypoint!(main);

use hash_merkle::{deterministic_leaves, merkle_root, HashMerkleParams};

pub fn main() {
    let leaves = sp1_zkvm::io::read::<usize>();
    let rounds = sp1_zkvm::io::read::<u32>();

    let params = HashMerkleParams { leaves, rounds };
    let root = merkle_root(deterministic_leaves(params));

    sp1_zkvm::io::commit_slice(&root);
}
