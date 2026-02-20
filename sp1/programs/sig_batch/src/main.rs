#![no_main]
sp1_zkvm::entrypoint!(main);

use sig_batch::{deterministic_messages, deterministic_pubkeys, simulated_verify, SigBatchParams};

pub fn main() {
    let batch_size = sp1_zkvm::io::read::<usize>();
    let rounds = sp1_zkvm::io::read::<u32>();

    let params = SigBatchParams { batch_size, rounds };
    let messages = deterministic_messages(params);
    let pubkeys = deterministic_pubkeys(params);
    let digest = simulated_verify(&messages, &pubkeys, rounds);

    sp1_zkvm::io::commit_slice(&digest);
}
