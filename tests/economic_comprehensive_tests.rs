//! Comprehensive Economic Parameters Tests
//!
//! Additional tests for economic parameters covering edge cases,
//! boundary conditions, and comprehensive halving scenarios.

use blvm_protocol::ProtocolVersion;
use blvm_protocol::economic::EconomicParameters;

#[test]
fn test_subsidy_all_halvings() {
    let params = EconomicParameters::mainnet();

    // Test all halving periods up to 64
    for halving in 0..64 {
        let start_height = halving * 210_000;
        let end_height = (halving + 1) * 210_000 - 1;
        let expected_subsidy = 50_0000_0000 >> halving;

        assert_eq!(params.get_block_subsidy(start_height), expected_subsidy);
        assert_eq!(params.get_block_subsidy(end_height), expected_subsidy);
    }
}

#[test]
fn test_subsidy_after_64_halvings() {
    let params = EconomicParameters::mainnet();

    // After 64 halvings, subsidy should be 0
    let height_64_halvings = 64 * 210_000;
    assert_eq!(params.get_block_subsidy(height_64_halvings), 0);
    assert_eq!(params.get_block_subsidy(height_64_halvings + 1000), 0);
    assert_eq!(params.get_block_subsidy(20_000_000), 0);
}

#[test]
fn test_total_supply_precise_calculation() {
    let params = EconomicParameters::mainnet();

    // Calculate total supply for first halving period
    let mut expected_total = 0u64;
    for h in 0..210_000 {
        expected_total = expected_total.saturating_add(params.get_block_subsidy(h));
    }

    let calculated_total = params.total_supply_at_height(209_999);
    assert_eq!(calculated_total, expected_total);
}

#[test]
fn test_total_supply_at_halving_boundaries() {
    let params = EconomicParameters::mainnet();

    // At first halving
    let total_at_halving = params.total_supply_at_height(210_000);
    assert!(total_at_halving > 0);

    // Should be: 210,000 blocks * 50 BTC = 10,500,000 BTC
    let expected_first_period = 210_000u64 * 50_0000_0000;
    assert_eq!(
        params.total_supply_at_height(209_999),
        expected_first_period
    );
}

#[test]
fn test_total_supply_saturation() {
    let params = EconomicParameters::mainnet();

    // Test that total supply calculation doesn't overflow
    let very_high_height = 100_000_000;
    let total = params.total_supply_at_height(very_high_height);

    // Should not exceed max money supply
    assert!(total <= params.max_money_supply);
}

#[test]
fn test_dust_limit_edge_cases() {
    let params = EconomicParameters::mainnet();

    // Exactly at dust limit
    assert!(!params.is_dust(546));

    // One below dust limit
    assert!(params.is_dust(545));

    // Zero value
    assert!(params.is_dust(0));

    // Very large value
    assert!(!params.is_dust(21_0000_0000_0000_0000));
}

#[test]
fn test_fee_rate_boundaries() {
    let params = EconomicParameters::mainnet();

    // Minimum valid fee rate
    assert!(params.is_valid_fee_rate(1));

    // Maximum valid fee rate
    assert!(params.is_valid_fee_rate(1_000_000));

    // Just below minimum
    assert!(!params.is_valid_fee_rate(0));

    // Just above maximum
    assert!(!params.is_valid_fee_rate(1_000_001));
}

#[test]
fn test_fee_calculation_edge_cases() {
    let params = EconomicParameters::mainnet();

    // Zero size transaction
    assert_eq!(params.calculate_fee(0, 10), 0);

    // Very large transaction
    assert_eq!(params.calculate_fee(1_000_000, 100), 100_000_000);

    // Minimum fee rate
    assert_eq!(params.calculate_fee(250, 1), 250);

    // Maximum fee rate
    assert_eq!(params.calculate_fee(250, 1_000_000), 250_000_000);

    // Invalid fee rate returns 0
    assert_eq!(params.calculate_fee(250, 0), 0);
    assert_eq!(params.calculate_fee(250, 1_000_001), 0);
}

#[test]
fn test_regtest_halving_edge_cases() {
    let params = EconomicParameters::regtest();

    // Test faster halving intervals
    assert_eq!(params.get_block_subsidy(0), 50_0000_0000);
    assert_eq!(params.get_block_subsidy(149), 50_0000_0000);
    assert_eq!(params.get_block_subsidy(150), 25_0000_0000);
    assert_eq!(params.get_block_subsidy(299), 25_0000_0000);
    assert_eq!(params.get_block_subsidy(300), 12_5000_0000);
    assert_eq!(params.get_block_subsidy(449), 12_5000_0000);
    assert_eq!(params.get_block_subsidy(450), 6_2500_0000);
}

#[test]
fn test_regtest_zero_fees() {
    let params = EconomicParameters::regtest();

    // Regtest allows zero fees
    assert!(params.is_valid_fee_rate(0));
    assert_eq!(params.calculate_fee(250, 0), 0);
    assert_eq!(params.min_fee_rate, 0);
    assert_eq!(params.min_relay_fee, 0);
}

#[test]
fn test_custom_subsidy_schedule_edge_cases() {
    let mut params = EconomicParameters::mainnet();

    // Empty schedule should use halving formula
    params.subsidy_schedule = Vec::new();
    assert_eq!(params.get_block_subsidy(0), 50_0000_0000);
    assert_eq!(params.get_block_subsidy(210_000), 25_0000_0000);

    // Single entry schedule
    params.subsidy_schedule = vec![(0, 100_0000_0000)];
    assert_eq!(params.get_block_subsidy(0), 100_0000_0000);
    assert_eq!(params.get_block_subsidy(1000), 100_0000_0000);

    // Schedule with gaps
    params.subsidy_schedule = vec![
        (0, 100_0000_0000),
        (1000, 50_0000_0000),
        (5000, 25_0000_0000),
    ];
    assert_eq!(params.get_block_subsidy(0), 100_0000_0000);
    assert_eq!(params.get_block_subsidy(999), 100_0000_0000);
    assert_eq!(params.get_block_subsidy(1000), 50_0000_0000);
    assert_eq!(params.get_block_subsidy(4999), 50_0000_0000);
    assert_eq!(params.get_block_subsidy(5000), 25_0000_0000);
    assert_eq!(params.get_block_subsidy(10000), 25_0000_0000);
}

#[test]
fn test_for_protocol_all_versions() {
    // Test that for_protocol returns correct parameters for all versions
    let mainnet = EconomicParameters::for_protocol(ProtocolVersion::BitcoinV1);
    let testnet = EconomicParameters::for_protocol(ProtocolVersion::Testnet3);
    let regtest = EconomicParameters::for_protocol(ProtocolVersion::Regtest);

    // Mainnet and testnet should be the same
    assert_eq!(mainnet.initial_subsidy, testnet.initial_subsidy);
    assert_eq!(mainnet.halving_interval, testnet.halving_interval);

    // Regtest should have different halving interval
    assert_ne!(mainnet.halving_interval, regtest.halving_interval);
    assert_eq!(regtest.halving_interval, 150);
}

#[test]
fn test_exceeds_max_supply_calculation() {
    let params = EconomicParameters::mainnet();

    // At reasonable heights, shouldn't exceed
    assert!(!params.exceeds_max_supply(100_000));
    assert!(!params.exceeds_max_supply(1_000_000));
    assert!(!params.exceeds_max_supply(10_000_000));

    // Check that max supply is correct
    assert_eq!(params.max_money_supply, 21_0000_0000_0000_0000);
}

#[test]
fn test_coinbase_maturity_all_networks() {
    let mainnet = EconomicParameters::mainnet();
    let testnet = EconomicParameters::testnet();
    let regtest = EconomicParameters::regtest();

    // All networks should have same coinbase maturity
    assert_eq!(mainnet.coinbase_maturity, 100);
    assert_eq!(testnet.coinbase_maturity, 100);
    assert_eq!(regtest.coinbase_maturity, 100);
}

#[test]
fn test_economic_parameters_clone() {
    let params = EconomicParameters::mainnet();
    let cloned = params.clone();

    assert_eq!(params, cloned);
    assert_eq!(params.initial_subsidy, cloned.initial_subsidy);
    assert_eq!(params.halving_interval, cloned.halving_interval);
}

#[test]
fn test_subsidy_precision() {
    let params = EconomicParameters::mainnet();

    // Test that subsidy calculations maintain precision
    // After 32 halvings, subsidy should be very small but not zero
    let height_32_halvings = 32 * 210_000;
    let subsidy = params.get_block_subsidy(height_32_halvings);
    assert!(subsidy > 0);
    assert!(subsidy < 50_0000_0000);
}
