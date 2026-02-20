use crate::config::{ProofMode, RunConfig};
use crate::report::{GasEstimate, PricingSnapshot};

pub fn estimate_usd(gas: u64, gas_gwei: f64, eth_usd: f64) -> f64 {
    gas as f64 * gas_gwei * 1e-9 * eth_usd
}

pub fn build_gas_table(cfg: &RunConfig, pricing: &PricingSnapshot) -> Vec<GasEstimate> {
    cfg.proof_modes
        .iter()
        .map(|mode| {
            let verify_gas = match mode {
                ProofMode::Compressed => None,
                ProofMode::Groth16 => Some(cfg.pricing.groth16_verify_gas),
                ProofMode::Plonk => Some(cfg.pricing.plonk_verify_gas),
            };
            let estimated_usd =
                verify_gas.map(|gas| estimate_usd(gas, pricing.gas_gwei, pricing.eth_usd));
            GasEstimate {
                proof_mode: mode.clone(),
                verify_gas,
                gas_gwei: pricing.gas_gwei,
                eth_usd: pricing.eth_usd,
                estimated_usd,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::estimate_usd;

    #[test]
    fn computes_usd() {
        let usd = estimate_usd(270_000, 5.0, 2_000.0);
        assert!(usd > 2.6 && usd < 2.8);
    }
}
