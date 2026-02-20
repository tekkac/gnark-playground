use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct VmStressParams {
    pub steps: usize,
    pub loops: usize,
}

pub fn execute(params: VmStressParams) -> [u8; 32] {
    let mut state: u64 = 0xDEADBEEFCAFEBABE;

    for i in 0..params.loops {
        for j in 0..params.steps {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add((i as u64) ^ ((j as u64) << 1))
                .rotate_left(13);
            state ^= state >> 7;
            state = state.rotate_right(3);
        }
    }

    let mut h = Sha256::new();
    h.update(b"vm_stress");
    h.update(state.to_le_bytes());
    h.update((params.steps as u64).to_le_bytes());
    h.update((params.loops as u64).to_le_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
