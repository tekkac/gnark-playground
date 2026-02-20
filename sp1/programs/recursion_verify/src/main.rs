#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let digests = sp1_zkvm::io::read::<Vec<([u32; 8], [u8; 32])>>();

    for (vk_digest, pv_digest) in &digests {
        sp1_zkvm::lib::verify::verify_sp1_proof(vk_digest, pv_digest);
    }

    let count = digests.len() as u32;
    sp1_zkvm::io::commit(&count);
    if let Some((_, last_digest)) = digests.last() {
        sp1_zkvm::io::commit_slice(last_digest);
    }
}
