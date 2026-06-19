//! Network parameters for different Bitcoin variants
//!
//! This module defines the network-specific parameters for different
//! Bitcoin protocol variants, including magic bytes, ports, genesis blocks,
//! and other network-specific constants.

use crate::{NetworkParameters, ProtocolVersion, Result};
use serde::{Deserialize, Serialize};

/// Network-specific constants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConstants {
    /// Network magic bytes for P2P protocol identification
    pub magic_bytes: [u8; 4],
    /// Default P2P port for this network
    pub default_port: u16,
    /// Genesis block hash for this network
    pub genesis_hash: [u8; 32],
    /// Maximum proof-of-work target
    pub max_target: u32,
    /// Block subsidy halving interval
    pub halving_interval: u64,
    /// Network name for identification
    pub network_name: String,
    /// Whether this is a test network
    pub is_testnet: bool,
    /// DNS seeds for peer discovery
    pub dns_seeds: Vec<String>,
    /// Checkpoint blocks for fast sync
    pub checkpoints: Vec<Checkpoint>,
}

/// Checkpoint block for fast synchronization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// Block timestamp
    pub timestamp: u64,
}

impl NetworkConstants {
    /// Get constants for a specific protocol version
    pub fn for_version(version: ProtocolVersion) -> Result<Self> {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
            ProtocolVersion::Signet => Self::signet(),
        }
    }

    /// Bitcoin mainnet constants
    pub fn mainnet() -> Result<Self> {
        Ok(Self {
            magic_bytes: [0xf9, 0xbe, 0xb4, 0xd9], // Bitcoin mainnet magic
            default_port: 8333,
            genesis_hash: [
                0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
                0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            max_target: 0x1d00ffff,
            halving_interval: 210000,
            network_name: "mainnet".to_string(),
            is_testnet: false,
            dns_seeds: vec![
                "seed.bitcoin.sipa.be".to_string(),
                "dnsseed.bluematt.me".to_string(),
                "dnsseed.bitcoin.dashjr.org".to_string(),
                "seed.bitcoinstats.com".to_string(),
                "seed.bitcoin.jonasschnelli.ch".to_string(),
                "seed.btc.petertodd.org".to_string(),
            ],
            checkpoints: Self::mainnet_checkpoints(),
        })
    }

    /// Bitcoin testnet constants
    pub fn testnet() -> Result<Self> {
        Ok(Self {
            magic_bytes: [0x0b, 0x11, 0x09, 0x07], // Bitcoin testnet magic
            default_port: 18333,
            genesis_hash: [
                0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce,
                0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09,
                0x00, 0x00, 0x00, 0x00,
            ],
            max_target: 0x1d00ffff,
            halving_interval: 210000,
            network_name: "testnet".to_string(),
            is_testnet: true,
            dns_seeds: vec![
                "testnet-seed.bitcoin.jonasschnelli.ch".to_string(),
                "seed.tbtc.petertodd.org".to_string(),
                "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                "testnet-seed.bluematt.me".to_string(),
            ],
            checkpoints: Self::testnet_checkpoints(),
        })
    }

    /// Bitcoin regtest constants
    pub fn regtest() -> Result<Self> {
        Ok(Self {
            magic_bytes: [0xfa, 0xbf, 0xb5, 0xda], // Bitcoin regtest magic
            default_port: 18444,
            genesis_hash: [
                0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb,
                0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c,
                0xf1, 0x88, 0x91, 0x0f,
            ],
            max_target: 0x207fffff, // Easier difficulty for testing
            halving_interval: 150,  // Faster halving for testing
            network_name: "regtest".to_string(),
            is_testnet: true,
            dns_seeds: vec![],   // No DNS seeds for regtest
            checkpoints: vec![], // No checkpoints for regtest
        })
    }

    /// Bitcoin signet constants (default public signet)
    pub fn signet() -> Result<Self> {
        Ok(Self {
            magic_bytes: [0x0f, 0x1b, 0xf2, 0xe1],
            default_port: 38333,
            genesis_hash: [
                0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2,
                0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81,
                0x08, 0x00, 0x00, 0x00,
            ],
            max_target: 0x1e0377ae,
            halving_interval: 210_000,
            network_name: "signet".to_string(),
            is_testnet: true,
            dns_seeds: vec![
                "seed.signet.bitcoin.sprovoost.nl".to_string(),
                "seed.signet.achownodes.xyz".to_string(),
            ],
            checkpoints: vec![],
        })
    }

    /// Mainnet checkpoints for fast sync
    fn mainnet_checkpoints() -> Vec<Checkpoint> {
        vec![
            Checkpoint {
                height: 11111,
                hash: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                timestamp: 1231006505,
            },
            // Add more checkpoints as needed
        ]
    }

    /// Testnet checkpoints for fast sync
    fn testnet_checkpoints() -> Vec<Checkpoint> {
        vec![
            Checkpoint {
                height: 11111,
                hash: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                timestamp: 1296688602,
            },
            // Add more checkpoints as needed
        ]
    }
}

impl NetworkParameters {
    /// Create network parameters from constants
    pub fn from_constants(constants: &NetworkConstants) -> Result<Self> {
        let genesis_block = match constants.network_name.as_str() {
            "testnet" => crate::genesis::testnet_genesis(),
            "regtest" => crate::genesis::regtest_genesis(),
            "signet" => crate::genesis::signet_genesis(),
            _ => crate::genesis::mainnet_genesis(),
        };
        Ok(NetworkParameters {
            magic_bytes: constants.magic_bytes,
            default_port: constants.default_port,
            genesis_block,
            max_target: constants.max_target,
            halving_interval: constants.halving_interval,
            network_name: constants.network_name.clone(),
            is_testnet: constants.is_testnet,
            signet_challenge: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_constants() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        assert_eq!(mainnet.magic_bytes, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(mainnet.default_port, 8333);
        assert!(!mainnet.is_testnet);
        assert!(!mainnet.dns_seeds.is_empty());

        let testnet = NetworkConstants::testnet().unwrap();
        assert_eq!(testnet.magic_bytes, [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(testnet.default_port, 18333);
        assert!(testnet.is_testnet);

        let regtest = NetworkConstants::regtest().unwrap();
        assert_eq!(regtest.magic_bytes, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(regtest.default_port, 18444);
        assert!(regtest.is_testnet);
        assert!(regtest.dns_seeds.is_empty());

        let signet = NetworkConstants::signet().unwrap();
        assert_eq!(signet.magic_bytes, [0x0f, 0x1b, 0xf2, 0xe1]);
        assert_eq!(signet.default_port, 38333);
        assert!(signet.is_testnet);
        assert!(!signet.dns_seeds.is_empty());
    }

    #[test]
    fn test_network_parameters_from_constants() {
        let constants = NetworkConstants::mainnet().unwrap();
        let params = NetworkParameters::from_constants(&constants).unwrap();

        assert_eq!(params.magic_bytes, constants.magic_bytes);
        assert_eq!(params.default_port, constants.default_port);
        assert_eq!(params.network_name, constants.network_name);
        assert_eq!(params.is_testnet, constants.is_testnet);
    }

    #[test]
    fn test_network_constants_for_version() {
        let mainnet = NetworkConstants::for_version(ProtocolVersion::BitcoinV1).unwrap();
        assert_eq!(mainnet.network_name, "mainnet");
        assert!(!mainnet.is_testnet);

        let testnet = NetworkConstants::for_version(ProtocolVersion::Testnet3).unwrap();
        assert_eq!(testnet.network_name, "testnet");
        assert!(testnet.is_testnet);

        let regtest = NetworkConstants::for_version(ProtocolVersion::Regtest).unwrap();
        assert_eq!(regtest.network_name, "regtest");
        assert!(regtest.is_testnet);

        let signet = NetworkConstants::for_version(ProtocolVersion::Signet).unwrap();
        assert_eq!(signet.network_name, "signet");
        assert!(signet.is_testnet);
    }

    #[test]
    fn test_genesis_hashes() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        // Verify genesis hashes are different for each network
        assert_ne!(mainnet.genesis_hash, testnet.genesis_hash);
        assert_ne!(testnet.genesis_hash, regtest.genesis_hash);
        assert_ne!(mainnet.genesis_hash, regtest.genesis_hash);

        let signet = NetworkConstants::signet().unwrap();
        assert_ne!(signet.genesis_hash, mainnet.genesis_hash);
        assert_ne!(signet.genesis_hash, testnet.genesis_hash);
        assert_ne!(signet.genesis_hash, regtest.genesis_hash);

        // Verify genesis hashes are not all zeros
        assert_ne!(mainnet.genesis_hash, [0u8; 32]);
        assert_ne!(testnet.genesis_hash, [0u8; 32]);
        assert_ne!(regtest.genesis_hash, [0u8; 32]);
    }

    #[test]
    fn test_dns_seeds() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        // Mainnet should have DNS seeds
        assert!(!mainnet.dns_seeds.is_empty());
        assert!(
            mainnet
                .dns_seeds
                .iter()
                .any(|seed| seed.contains("bitcoin"))
        );

        // Testnet should have DNS seeds
        assert!(!testnet.dns_seeds.is_empty());
        assert!(
            testnet
                .dns_seeds
                .iter()
                .any(|seed| seed.contains("testnet"))
        );

        // Regtest should have no DNS seeds
        assert!(regtest.dns_seeds.is_empty());
    }

    #[test]
    fn test_checkpoints() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        // Mainnet should have checkpoints
        assert!(!mainnet.checkpoints.is_empty());

        // Testnet should have checkpoints
        assert!(!testnet.checkpoints.is_empty());

        // Regtest should have no checkpoints
        assert!(regtest.checkpoints.is_empty());

        // Check that checkpoints are ordered by height
        for checkpoints in [&mainnet.checkpoints, &testnet.checkpoints] {
            for i in 1..checkpoints.len() {
                assert!(checkpoints[i].height > checkpoints[i - 1].height);
            }
        }
    }

    #[test]
    fn test_max_targets() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        // Mainnet and testnet should have same max target
        assert_eq!(mainnet.max_target, 0x1d00ffff);
        assert_eq!(testnet.max_target, 0x1d00ffff);

        // Regtest should have easier difficulty
        assert_eq!(regtest.max_target, 0x207fffff);
        assert!(regtest.max_target > mainnet.max_target);
    }

    #[test]
    fn test_halving_intervals() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        // Mainnet and testnet should have same halving interval
        assert_eq!(mainnet.halving_interval, 210000);
        assert_eq!(testnet.halving_interval, 210000);

        // Regtest should have faster halving for testing
        assert_eq!(regtest.halving_interval, 150);
        assert!(regtest.halving_interval < mainnet.halving_interval);
    }

    #[test]
    fn test_network_constants_serialization() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        // Test serialization/deserialization
        for constants in [mainnet, testnet, regtest] {
            let json = serde_json::to_string(&constants).unwrap();
            let deserialized: NetworkConstants = serde_json::from_str(&json).unwrap();

            assert_eq!(constants.magic_bytes, deserialized.magic_bytes);
            assert_eq!(constants.default_port, deserialized.default_port);
            assert_eq!(constants.genesis_hash, deserialized.genesis_hash);
            assert_eq!(constants.max_target, deserialized.max_target);
            assert_eq!(constants.halving_interval, deserialized.halving_interval);
            assert_eq!(constants.network_name, deserialized.network_name);
            assert_eq!(constants.is_testnet, deserialized.is_testnet);
            assert_eq!(constants.dns_seeds, deserialized.dns_seeds);
            assert_eq!(constants.checkpoints, deserialized.checkpoints);
        }
    }

    #[test]
    fn test_checkpoint_serialization() {
        let checkpoint = Checkpoint {
            height: 1000,
            hash: [
                0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
                0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04,
            ],
            timestamp: 1234567890,
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(checkpoint.height, deserialized.height);
        assert_eq!(checkpoint.hash, deserialized.hash);
        assert_eq!(checkpoint.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_network_constants_equality() {
        let mainnet1 = NetworkConstants::mainnet().unwrap();
        let mainnet2 = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();

        assert_eq!(mainnet1, mainnet2);
        assert_ne!(mainnet1, testnet);
    }

    #[test]
    fn test_checkpoint_equality() {
        let checkpoint1 = Checkpoint {
            height: 1000,
            hash: [0x01; 32],
            timestamp: 1234567890,
        };

        let checkpoint2 = Checkpoint {
            height: 1000,
            hash: [0x01; 32],
            timestamp: 1234567890,
        };

        let checkpoint3 = Checkpoint {
            height: 1001,
            hash: [0x01; 32],
            timestamp: 1234567890,
        };

        assert_eq!(checkpoint1, checkpoint2);
        assert_ne!(checkpoint1, checkpoint3);
    }

    #[test]
    fn test_network_parameters_consistency() {
        let mainnet_constants = NetworkConstants::mainnet().unwrap();
        let mainnet_params = NetworkParameters::from_constants(&mainnet_constants).unwrap();

        assert_eq!(mainnet_params.magic_bytes, mainnet_constants.magic_bytes);
        assert_eq!(mainnet_params.default_port, mainnet_constants.default_port);
        assert_eq!(mainnet_params.max_target, mainnet_constants.max_target);
        assert_eq!(
            mainnet_params.halving_interval,
            mainnet_constants.halving_interval
        );
        assert_eq!(mainnet_params.network_name, mainnet_constants.network_name);
        assert_eq!(mainnet_params.is_testnet, mainnet_constants.is_testnet);
    }

    #[test]
    fn test_all_networks_have_unique_magic_bytes() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        assert_ne!(mainnet.magic_bytes, testnet.magic_bytes);
        assert_ne!(testnet.magic_bytes, regtest.magic_bytes);
        assert_ne!(mainnet.magic_bytes, regtest.magic_bytes);
    }

    #[test]
    fn test_all_networks_have_unique_ports() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        assert_ne!(mainnet.default_port, testnet.default_port);
        assert_ne!(testnet.default_port, regtest.default_port);
        assert_ne!(mainnet.default_port, regtest.default_port);
    }

    #[test]
    fn test_network_names() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        assert_eq!(mainnet.network_name, "mainnet");
        assert_eq!(testnet.network_name, "testnet");
        assert_eq!(regtest.network_name, "regtest");
    }

    #[test]
    fn test_testnet_flags() {
        let mainnet = NetworkConstants::mainnet().unwrap();
        let testnet = NetworkConstants::testnet().unwrap();
        let regtest = NetworkConstants::regtest().unwrap();

        assert!(!mainnet.is_testnet);
        assert!(testnet.is_testnet);
        assert!(regtest.is_testnet);
    }
}
