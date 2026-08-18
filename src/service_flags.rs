//! Service flags for Bitcoin P2P protocol
//!
//! Defines service flags used in Version messages to indicate node capabilities.
//! Includes standard Bitcoin flags and Commons-specific extensions.

/// Standard Bitcoin service flags (from Bitcoin Core)
pub mod standard {
    /// Node network (always set)
    pub const NODE_NETWORK: u64 = 1 << 0;

    /// Node GetUTXO (deprecated)
    pub const NODE_GETUTXO: u64 = 1 << 1;

    /// Node Bloom (deprecated)
    pub const NODE_BLOOM: u64 = 1 << 2;

    /// Node Witness (SegWit support)
    pub const NODE_WITNESS: u64 = 1 << 3;

    /// Node Xthin (deprecated)
    pub const NODE_XTHIN: u64 = 1 << 4;

    /// Node Compact Filters (BIP157)
    pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;

    /// Node Network Limited (pruned node)
    pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

    /// Node supports BIP324 v2 encrypted transport
    #[cfg(feature = "bip324")]
    pub const NODE_V2_TRANSPORT: u64 = 1 << 11;
}

/// Commons-specific service flags
pub mod commons {
    /// Node supports Dandelion++ privacy relay
    pub const NODE_DANDELION: u64 = 1 << 24;

    /// Node supports Package Relay (BIP331)
    pub const NODE_PACKAGE_RELAY: u64 = 1 << 25;

    /// Node supports FIBRE (Fast Internet Bitcoin Relay Engine)
    pub const NODE_FIBRE: u64 = 1 << 26;

    /// Node supports UTXO Commitments protocol (bit 27).
    #[cfg(feature = "utxo-commitments")]
    pub const NODE_UTXO_COMMITMENTS: u64 = 1 << 27;

    /// Node supports Ban List Sharing
    pub const NODE_BAN_LIST_SHARING: u64 = 1 << 28;

    /// Node supports governance-related P2P capability (advertised via Version.services)
    pub const NODE_GOVERNANCE: u64 = 1 << 29;

    /// Erlay (BIP330) transaction relay
    pub const NODE_ERLAY: u64 = 1 << 30;
}

pub use commons::*;
/// Re-export commonly used flags
pub use standard::*;

/// Check if a service flag is set
#[inline]
pub fn has_flag(services: u64, flag: u64) -> bool {
    (services & flag) != 0
}

/// Set a service flag
#[inline]
pub fn set_flag(services: &mut u64, flag: u64) {
    *services |= flag;
}

/// Clear a service flag
#[inline]
pub fn clear_flag(services: &mut u64, flag: u64) -> bool {
    let had_flag = has_flag(*services, flag);
    *services &= !flag;
    had_flag
}

/// Get all Commons-specific flags
pub fn get_commons_flags() -> u64 {
    let mut flags = 0u64;
    #[cfg(feature = "utxo-commitments")]
    {
        flags |= commons::NODE_UTXO_COMMITMENTS;
    }
    flags |= commons::NODE_DANDELION
        | commons::NODE_PACKAGE_RELAY
        | commons::NODE_FIBRE
        | commons::NODE_BAN_LIST_SHARING;
    flags
}

/// Check if node supports Commons features
pub fn supports_commons(services: u64) -> bool {
    has_flag(services, commons::NODE_FIBRE)
        || has_flag(services, commons::NODE_BAN_LIST_SHARING)
        || {
            #[cfg(feature = "utxo-commitments")]
            {
                has_flag(services, commons::NODE_UTXO_COMMITMENTS)
            }
            #[cfg(not(feature = "utxo-commitments"))]
            {
                false
            }
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_flag() {
        let services = standard::NODE_NETWORK | standard::NODE_WITNESS;
        assert!(has_flag(services, standard::NODE_NETWORK));
        assert!(has_flag(services, standard::NODE_WITNESS));
        assert!(!has_flag(services, standard::NODE_BLOOM));
    }

    #[test]
    fn test_set_flag() {
        let mut services = 0u64;
        set_flag(&mut services, standard::NODE_NETWORK);
        assert!(has_flag(services, standard::NODE_NETWORK));
    }

    #[test]
    fn test_clear_flag() {
        let mut services = standard::NODE_NETWORK | standard::NODE_WITNESS;
        assert!(clear_flag(&mut services, standard::NODE_NETWORK));
        assert!(!has_flag(services, standard::NODE_NETWORK));
        assert!(has_flag(services, standard::NODE_WITNESS));
    }

    #[test]
    fn test_commons_flags() {
        let flags = get_commons_flags();
        assert!(has_flag(flags, commons::NODE_DANDELION));
        assert!(has_flag(flags, commons::NODE_PACKAGE_RELAY));
        assert!(has_flag(flags, commons::NODE_FIBRE));
        assert!(has_flag(flags, commons::NODE_BAN_LIST_SHARING));
    }

    #[test]
    fn test_supports_commons() {
        let services = commons::NODE_FIBRE | standard::NODE_NETWORK;
        assert!(supports_commons(services));
    }
}
