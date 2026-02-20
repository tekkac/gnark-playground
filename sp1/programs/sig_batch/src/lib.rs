use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct SigBatchParams {
    pub batch_size: usize,
    pub rounds: u32,
}

pub fn deterministic_messages(params: SigBatchParams) -> Vec<[u8; 32]> {
    (0..params.batch_size)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"sig_batch_message");
            h.update((i as u64).to_le_bytes());
            h.update((params.rounds as u64).to_le_bytes());
            let digest = h.finalize();
            let mut msg = [0u8; 32];
            msg.copy_from_slice(&digest[..32]);
            msg
        })
        .collect()
}

pub fn deterministic_pubkeys(params: SigBatchParams) -> Vec<[u8; 32]> {
    (0..params.batch_size)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"sig_batch_pubkey");
            h.update((i as u64).to_le_bytes());
            h.update((params.rounds as u64).to_le_bytes());
            let digest = h.finalize();
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&digest[..32]);
            pk
        })
        .collect()
}

pub fn simulated_verify(messages: &[[u8; 32]], pubkeys: &[[u8; 32]], rounds: u32) -> [u8; 32] {
    let mut acc = [0u8; 32];

    for (m, pk) in messages.iter().zip(pubkeys.iter()) {
        let mut h = Sha256::new();
        h.update(acc);
        h.update(m);
        h.update(pk);
        let mut out = h.finalize().to_vec();

        for _ in 0..rounds {
            let mut inner = Sha256::new();
            inner.update(&out);
            out = inner.finalize().to_vec();
        }

        acc.copy_from_slice(&out[..32]);
    }

    acc
}
