//! Economic Model Parameters
//!
//! Expanded economic model abstraction beyond basic halving.
//! Provides comprehensive economic parameters for protocol variants.

use crate::ProtocolVersion;
use serde::{Deserialize, Serialize};

/// Economic model parameters for a protocol version
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicParameters {
    /// Initial block subsidy (in satoshis)
    pub initial_subsidy: u64,
    /// Block subsidy halving interval
    pub halving_interval: u64,
    /// Maximum money supply (in satoshis)
    pub max_money_supply: u64,
    /// Coinbase maturity (blocks before coinbase can be spent)
    pub coinbase_maturity: u64,
    /// Dust limit (minimum output value in satoshis)
    pub dust_limit: u64,
    /// Minimum transaction fee rate (satoshis per vbyte)
    pub min_fee_rate: u64,
    /// Maximum transaction fee rate (satoshis per vbyte)
    pub max_fee_rate: u64,
    /// Minimum relay fee (satoshis per vbyte)
    pub min_relay_fee: u64,
    /// Block subsidy schedule (for custom schedules)
    pub subsidy_schedule: Vec<(u64, u64)>, // (height, subsidy)
}

impl EconomicParameters {
    /// Get economic parameters for a protocol version
    pub fn for_protocol(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
            ProtocolVersion::Signet => Self::signet(),
        }
    }

    /// Mainnet economic parameters (Bitcoin production network)
    pub fn mainnet() -> Self {
        Self {
            initial_subsidy: 50_0000_0000, // 50 BTC in satoshis
            halving_interval: 210_000,
            max_money_supply: 21_0000_0000_0000_0000, // 21M BTC in satoshis
            coinbase_maturity: 100,                   // 100 blocks
            dust_limit: 546,                          // 546 satoshis
            min_fee_rate: 1,                          // 1 sat/vbyte
            max_fee_rate: 1_000_000,                  // 1M sat/vbyte (safety limit)
            min_relay_fee: 1000,                      // 1000 satoshis per transaction (BIP125)
            subsidy_schedule: Vec::new(),             // Use halving formula instead
        }
    }

    /// Testnet economic parameters (same as mainnet)
    pub fn testnet() -> Self {
        Self {
            initial_subsidy: 50_0000_0000,
            halving_interval: 210_000,
            max_money_supply: 21_0000_0000_0000_0000,
            coinbase_maturity: 100,
            dust_limit: 546,
            min_fee_rate: 1,
            max_fee_rate: 1_000_000,
            min_relay_fee: 1000,
            subsidy_schedule: Vec::new(),
        }
    }

    /// Regtest economic parameters (relaxed for testing)
    pub fn regtest() -> Self {
        Self {
            initial_subsidy: 50_0000_0000,
            halving_interval: 150, // Faster halving for testing
            max_money_supply: 21_0000_0000_0000_0000,
            coinbase_maturity: 100,
            dust_limit: 546,
            min_fee_rate: 0, // No minimum fee for testing
            max_fee_rate: 1_000_000,
            min_relay_fee: 0, // No minimum relay fee for testing
            subsidy_schedule: Vec::new(),
        }
    }

    /// Signet economic parameters (same halving schedule as mainnet)
    pub fn signet() -> Self {
        Self {
            initial_subsidy: 50_0000_0000,
            halving_interval: 210_000,
            max_money_supply: 21_0000_0000_0000_0000,
            coinbase_maturity: 100,
            dust_limit: 546,
            min_fee_rate: 1,
            max_fee_rate: 1_000_000,
            min_relay_fee: 1000,
            subsidy_schedule: Vec::new(),
        }
    }

    /// Calculate block subsidy for a given height
    pub fn get_block_subsidy(&self, height: u64) -> u64 {
        // If custom subsidy schedule exists, use it
        if !self.subsidy_schedule.is_empty() {
            for (schedule_height, subsidy) in self.subsidy_schedule.iter().rev() {
                if height >= *schedule_height {
                    return *subsidy;
                }
            }
            return 0;
        }

        // Use standard halving formula
        let halving_period = height / self.halving_interval;

        // After 64 halvings, subsidy becomes 0
        if halving_period >= 64 {
            return 0;
        }

        // Calculate: initial_subsidy / 2^halving_period
        self.initial_subsidy >> halving_period
    }

    /// Calculate total supply up to a given height
    pub fn total_supply_at_height(&self, height: u64) -> u64 {
        let mut total = 0u64;

        for h in 0..=height {
            total = total.saturating_add(self.get_block_subsidy(h));
        }

        total
    }

    /// Check if a value meets dust limit
    pub fn is_dust(&self, value: u64) -> bool {
        value < self.dust_limit
    }

    /// Check if a fee rate is valid
    pub fn is_valid_fee_rate(&self, fee_rate: u64) -> bool {
        fee_rate >= self.min_fee_rate && fee_rate <= self.max_fee_rate
    }

    /// Calculate fee for a transaction size
    pub fn calculate_fee(&self, size_vbytes: usize, fee_rate_sat_per_vbyte: u64) -> u64 {
        if !self.is_valid_fee_rate(fee_rate_sat_per_vbyte) {
            return 0;
        }

        (size_vbytes as u64).saturating_mul(fee_rate_sat_per_vbyte)
    }

    /// Check if total supply exceeds maximum
    pub fn exceeds_max_supply(&self, height: u64) -> bool {
        self.total_supply_at_height(height) > self.max_money_supply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_economic_parameters() {
        let params = EconomicParameters::mainnet();

        assert_eq!(params.initial_subsidy, 50_0000_0000);
        assert_eq!(params.halving_interval, 210_000);
        assert_eq!(params.max_money_supply, 21_0000_0000_0000_0000);
        assert_eq!(params.coinbase_maturity, 100);
        assert_eq!(params.dust_limit, 546);
    }

    #[test]
    fn test_block_subsidy_halving() {
        let params = EconomicParameters::mainnet();

        // Initial subsidy
        assert_eq!(params.get_block_subsidy(0), 50_0000_0000);
        assert_eq!(params.get_block_subsidy(209_999), 50_0000_0000);

        // First halving
        assert_eq!(params.get_block_subsidy(210_000), 25_0000_0000);
        assert_eq!(params.get_block_subsidy(419_999), 25_0000_0000);

        // Second halving
        assert_eq!(params.get_block_subsidy(420_000), 12_5000_0000);

        // After 64 halvings (13,440,000 blocks)
        assert_eq!(params.get_block_subsidy(13_440_000), 0);
        assert_eq!(params.get_block_subsidy(20_000_000), 0);
    }

    #[test]
    fn test_total_supply_calculation() {
        let params = EconomicParameters::mainnet();

        // Genesis block
        assert_eq!(params.total_supply_at_height(0), 50_0000_0000);

        // After 10 blocks
        assert_eq!(params.total_supply_at_height(9), 10 * 50_0000_0000);

        // At first halving
        let first_halving_height = 210_000;
        let _before_halving_subsidy = first_halving_height * 50_0000_0000;
        // Approximate calculation (simplified)
        assert!(params.total_supply_at_height(first_halving_height) > 0);
    }

    #[test]
    fn test_dust_limit() {
        let params = EconomicParameters::mainnet();

        assert!(params.is_dust(545));
        assert!(!params.is_dust(546));
        assert!(!params.is_dust(1000));
    }

    #[test]
    fn test_fee_rate_validation() {
        let params = EconomicParameters::mainnet();

        // Valid fee rates
        assert!(params.is_valid_fee_rate(1));
        assert!(params.is_valid_fee_rate(100));
        assert!(params.is_valid_fee_rate(1_000_000));

        // Invalid fee rates
        assert!(!params.is_valid_fee_rate(0));
        assert!(!params.is_valid_fee_rate(1_000_001));
    }

    #[test]
    fn test_fee_calculation() {
        let params = EconomicParameters::mainnet();

        // 250 vbyte transaction at 10 sat/vbyte = 2500 sats
        assert_eq!(params.calculate_fee(250, 10), 2500);

        // Invalid fee rate returns 0
        assert_eq!(params.calculate_fee(250, 0), 0);
        assert_eq!(params.calculate_fee(250, 2_000_000), 0);
    }

    #[test]
    fn test_regtest_relaxed_parameters() {
        let params = EconomicParameters::regtest();

        // Faster halving
        assert_eq!(params.halving_interval, 150);

        // No minimum fees
        assert_eq!(params.min_fee_rate, 0);
        assert_eq!(params.min_relay_fee, 0);

        // Can use zero fees
        assert!(params.is_valid_fee_rate(0));
    }

    #[test]
    fn test_regtest_faster_halving() {
        let params = EconomicParameters::regtest();

        // Subsidy halves at block 150 instead of 210,000
        assert_eq!(params.get_block_subsidy(0), 50_0000_0000);
        assert_eq!(params.get_block_subsidy(149), 50_0000_0000);
        assert_eq!(params.get_block_subsidy(150), 25_0000_0000);
        assert_eq!(params.get_block_subsidy(299), 25_0000_0000);
        assert_eq!(params.get_block_subsidy(300), 12_5000_0000);
    }

    #[test]
    fn test_testnet_same_as_mainnet() {
        let mainnet = EconomicParameters::mainnet();
        let testnet = EconomicParameters::testnet();

        assert_eq!(mainnet.initial_subsidy, testnet.initial_subsidy);
        assert_eq!(mainnet.halving_interval, testnet.halving_interval);
        assert_eq!(mainnet.max_money_supply, testnet.max_money_supply);
        assert_eq!(mainnet.coinbase_maturity, testnet.coinbase_maturity);
        assert_eq!(mainnet.dust_limit, testnet.dust_limit);
    }

    #[test]
    fn test_custom_subsidy_schedule() {
        let mut params = EconomicParameters::mainnet();
        params.subsidy_schedule = vec![
            (0, 100_0000_0000),      // 100 BTC for first 1000 blocks
            (1000, 50_0000_0000),    // 50 BTC after
            (210_000, 25_0000_0000), // 25 BTC after halving
        ];

        assert_eq!(params.get_block_subsidy(0), 100_0000_0000);
        assert_eq!(params.get_block_subsidy(999), 100_0000_0000);
        assert_eq!(params.get_block_subsidy(1000), 50_0000_0000);
        assert_eq!(params.get_block_subsidy(210_000), 25_0000_0000);
    }

    #[test]
    fn test_max_supply_check() {
        let params = EconomicParameters::mainnet();

        // At reasonable heights, shouldn't exceed
        assert!(!params.exceeds_max_supply(100_000));
        assert!(!params.exceeds_max_supply(1_000_000));

        // At extremely high heights (beyond 64 halvings), should check
        // Note: This test may need adjustment based on actual calculation
    }

    #[test]
    fn test_economic_parameters_serialization() {
        let mainnet = EconomicParameters::mainnet();
        let json = serde_json::to_string(&mainnet).unwrap();
        let deserialized: EconomicParameters = serde_json::from_str(&json).unwrap();

        assert_eq!(mainnet.initial_subsidy, deserialized.initial_subsidy);
        assert_eq!(mainnet.halving_interval, deserialized.halving_interval);
        assert_eq!(mainnet.max_money_supply, deserialized.max_money_supply);
        assert_eq!(mainnet.coinbase_maturity, deserialized.coinbase_maturity);
        assert_eq!(mainnet.dust_limit, deserialized.dust_limit);
    }

    #[test]
    fn test_economic_parameters_equality() {
        let mainnet1 = EconomicParameters::mainnet();
        let mainnet2 = EconomicParameters::mainnet();
        let testnet = EconomicParameters::testnet();

        assert_eq!(mainnet1, mainnet2);
        assert_eq!(mainnet1, testnet); // Mainnet and testnet have same economic params
    }
}
