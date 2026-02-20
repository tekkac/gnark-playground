use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct HashMerkleParams {
    pub leaves: usize,
    pub rounds: u32,
}

pub fn deterministic_leaves(params: HashMerkleParams) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(params.leaves);
    for i in 0..params.leaves {
        let mut h = Sha256::new();
        h.update(b"hash_merkle");
        h.update((i as u64).to_le_bytes());
        h.update((params.rounds as u64).to_le_bytes());
        let mut v = h.finalize().to_vec();
        for _ in 0..params.rounds {
            let mut inner = Sha256::new();
            inner.update(&v);
            v = inner.finalize().to_vec();
        }
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&v[..32]);
        out.push(leaf);
    }
    out
}

pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for chunk in leaves.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            let digest = h.finalize();
            let mut node = [0u8; 32];
            node.copy_from_slice(&digest[..32]);
            next.push(node);
        }
        leaves = next;
    }

    leaves[0]
}
