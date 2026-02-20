#![no_main]
sp1_zkvm::entrypoint!(main);

use vm_stress::{execute, VmStressParams};

pub fn main() {
    let steps = sp1_zkvm::io::read::<usize>();
    let loops = sp1_zkvm::io::read::<usize>();

    let out = execute(VmStressParams { steps, loops });
    sp1_zkvm::io::commit_slice(&out);
}
