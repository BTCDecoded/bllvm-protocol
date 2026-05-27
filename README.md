# Bitcoin Protocol Engine

[![crates.io](https://img.shields.io/crates/v/blvm-protocol.svg)](https://crates.io/crates/blvm-protocol)
[![docs.rs](https://docs.rs/blvm-protocol/badge.svg)](https://docs.rs/blvm-protocol)
[![CI](https://github.com/BTCDecoded/blvm-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BTCDecoded/blvm-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Bitcoin protocol abstraction layer supporting multiple variants and protocol evolution.

> **For verified system status**: See [SYSTEM_STATUS.md](https://github.com/BTCDecoded/.github/blob/main/SYSTEM_STATUS.md) in the BTCDecoded organization repository.

Provides a Bitcoin protocol abstraction layer enabling:
- Multiple Bitcoin variants (mainnet, testnet, regtest)
- Protocol evolution support
- Economic model abstraction
- Commons-specific protocol extensions (UTXO commitments, ban list sharing)
- Research-friendly interfaces

## Architecture Position

Tier 3 of the 6-tier Bitcoin Commons architecture (BLVM technology stack):

```
1. blvm-spec (Orange Paper - mathematical foundation)
2. blvm-consensus (pure math implementation)
3. blvm-protocol (Bitcoin abstraction)
4. blvm-node (full node implementation)
5. blvm-sdk (developer toolkit)
6. blvm-commons (governance enforcement)
```

## Formal verification (CI)

The **verify** job in **`.github/workflows/ci.yml`** installs **`cargo-spec-lock`** from crates.io, runs **`check-drift`**, then **`cargo spec-lock verify`** with **`--spec-path`** (merged **`F_*`** registry + **`#[spec_locked]`** rows; **`formula_registry`** nested in **`spec_lock_verify.json`**). JSON fields and **`jq`**: **`blvm-spec-lock`** **`docs/VERIFY_JSON.md`**.

## Features

- **Protocol Variants**: Mainnet, testnet, regtest support
- **Network Messages**: Core P2P messages and BIP152 compact blocks
- **FIBRE Protocol**: High-performance relay protocol with packet format definitions
- **Governance P2P surfaces**: Optional commons-related P2P messages and flags — see **`NetworkMessage` / `src/`** and the **[published book](https://docs.thebitcoincommons.org)** protocol chapters.
- **Commons Extensions**: UTXO commitments, filtered blocks, ban list sharing
- **Service Flags**: Standard and Commons-specific capability flags
- **Validation Rules**: Protocol-specific size limits and validation
- **BIP Support**: BIP152, BIP157, BIP158, BIP173/350/351
- **DoS Protection**: Protocol-level message size limits

## Purpose

Sits between pure mathematical consensus rules (blvm-consensus) and full Bitcoin implementation (blvm-node). Provides:

### Protocol Abstraction
- **Multiple Variants**: Support for mainnet, testnet, and regtest
- **Network Parameters**: Magic bytes, ports, genesis blocks, difficulty targets
- **Feature Flags**: SegWit, Taproot, RBF, and other protocol features
- **Validation Rules**: Protocol-specific size limits and validation logic

### Protocol Evolution
- **Version Support**: Multiple protocol versions
- **Feature Management**: Enable/disable features based on protocol version
- **Breaking Changes**: Track and manage protocol evolution

### Commons-Specific Extensions
- **UTXO Commitments**: Protocol messages for UTXO set synchronization and verification
- **Filtered Blocks**: Spam-filtered block relay for efficient syncing
- **Ban List Sharing**: Distributed ban list management
- **Service Flags**: Standard and Commons-specific capability flags

## Core Components

### Protocol Variants
- **BitcoinV1**: Production Bitcoin mainnet
- **Testnet3**: Bitcoin test network
- **Regtest**: Regression testing network

### Network Parameters
- **Magic Bytes**: P2P protocol identification
- **Ports**: Default network ports
- **Genesis Blocks**: Network-specific genesis blocks
- **Difficulty**: Proof-of-work targets
- **Halving**: Block subsidy intervals

### Network Messages
- **Core P2P Messages**: Version, VerAck, Addr, Inv, GetData, GetHeaders, Headers, Block, Tx, Ping, Pong, MemPool, FeeFilter
- **Additional Core Messages**: GetBlocks, GetAddr, NotFound, Reject, SendHeaders
- **BIP152 (Compact Block Relay)**: SendCmpct, CmpctBlock, GetBlockTxn, BlockTxn
- **Commons Extensions**: GetUTXOSet, UTXOSet, GetFilteredBlock, FilteredBlock, GetBanList, BanList

### Service Flags
- **Standard Flags**: NODE_NETWORK, NODE_WITNESS, NODE_COMPACT_FILTERS, NODE_NETWORK_LIMITED
- **Commons Flags**: NODE_UTXO_COMMITMENTS, NODE_BAN_LIST_SHARING, NODE_FIBRE, NODE_DANDELION, NODE_PACKAGE_RELAY

### Validation Rules
- **Size Limits**: Block, transaction, and script size limits
- **Feature Flags**: SegWit, Taproot, RBF support
- **Fee Rules**: Minimum and maximum fee rates
- **Protocol Context**: Block height and network state
- **DoS Protection**: Protocol-level message size limits

## Usage

### Basic Protocol Engine

```rust
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

// Create a mainnet protocol engine
let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;

// Get network parameters
let params = engine.get_network_params();
println!("Network: {}", params.network_name);
println!("Port: {}", params.default_port);

// Check feature support
if engine.supports_feature("segwit") {
    println!("SegWit is supported");
}
```

### Configuration

```rust
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion, ProtocolConfig};

// Create protocol configuration
let mut config = ProtocolConfig::default();
config.service_flags.node_fibre = true;
config.commons.utxo_commitments = true;
config.validation.max_block_size = 4_000_000;

// Load from environment variables
let config = ProtocolConfig::from_env();

// Get service flags from configuration
let service_flags = config.get_service_flags();
```

### Configuration Options

The protocol configuration system provides:

- **Protocol Validation**: Size limits (block, transaction, script), transaction count limits, locator hash limits
- **Service Flags**: Control which capabilities are advertised (NODE_NETWORK, NODE_WITNESS, Commons extensions)
- **Protocol Features**: Enable/disable SegWit, Taproot, RBF, CTV, Compact Blocks, Compact Filters
- **Fee Rates**: Minimum and maximum fee rate limits
- **Compact Blocks**: BIP152 configuration (version preference, index limits)
- **Commons Extensions**: UTXO commitments, filtered blocks, ban list sharing, filter preferences
- **FIBRE**: Fast Internet Bitcoin Relay Engine configuration

Configuration can be loaded from:
- Environment variables (`BLVM_PROTOCOL_<SECTION>_<KEY>`)
- Programmatic configuration (struct initialization)
- Configuration files (via serde serialization)

### Service Flags

```rust
use blvm_protocol::service_flags::{self, standard, commons};

// Check service flags
let services = standard::NODE_NETWORK | standard::NODE_WITNESS | commons::NODE_FIBRE;
assert!(service_flags::has_flag(services, standard::NODE_NETWORK));
assert!(service_flags::has_flag(services, commons::NODE_FIBRE));

// Get all Commons flags
let commons_flags = service_flags::get_commons_flags();
assert!(service_flags::has_flag(commons_flags, commons::NODE_FIBRE));
assert!(service_flags::has_flag(commons_flags, commons::NODE_BAN_LIST_SHARING));
```

### Network Message Processing

```rust
use blvm_protocol::network::{process_network_message, NetworkMessage, PeerState};
use blvm_protocol::BitcoinProtocolEngine;

let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;
let mut peer_state = PeerState::new();

// Process a version message
let version_msg = NetworkMessage::Version(/* ... */);
let response = process_network_message(
    &engine,
    &version_msg,
    &mut peer_state,
    None,
    None,
    None,
)?;
```

### Commons Protocol Extensions

```rust
use blvm_protocol::commons::{GetUTXOSetMessage, GetBanListMessage};
use blvm_protocol::network::NetworkMessage;

// Request UTXO set at specific height
let get_utxo = NetworkMessage::GetUTXOSet(GetUTXOSetMessage {
    height: 700000,
    block_hash: [/* ... */],
});

// Request ban list
let get_banlist = NetworkMessage::GetBanList(GetBanListMessage {
    request_id: 12345,
    min_score: Some(100),
});
```

### BIP152 Compact Block Relay

```rust
use blvm_protocol::network::{NetworkMessage, SendCmpctMessage};

// Negotiate compact block relay
let sendcmpct = NetworkMessage::SendCmpct(SendCmpctMessage {
    version: 2,  // Compact block version
    prefer_cmpct: 1,  // Prefer compact blocks
});
```

### Protocol-Specific Validation

```rust
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;

// Validate block with protocol rules
let result = engine.validate_block(&block, &utxos, height)?;

// Validate transaction with protocol rules
let result = engine.validate_transaction(&tx)?;
```

### Regtest Mode

```rust
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

// Create regtest protocol engine
let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest)?;

// Regtest mode has fast mining for testing
assert!(engine.supports_feature("fast_mining"));
assert!(engine.supports_feature("segwit"));
```

## Protocol Evolution

### Supported Protocol Features
- Basic transactions and proof-of-work
- Economic model and P2P networking
- SegWit and Taproot support
- RBF (Replace-By-Fee) support
- BIP152 Compact Block Relay
- BIP157 Block Filtering

### Commons Extensions
- UTXO Commitments protocol
- Filtered block relay (spam filtering)
- Ban list sharing
- FIBRE support
- Dandelion++ privacy relay

### Protocol Version Support
- Multiple protocol versions supported
- Enhanced scripting capabilities
- Privacy features
- Advanced economic models
- Protocol improvements

## Modules

### Core Modules
- `network` - P2P network message types and processing
- `service_flags` - Service flags for node capabilities
- `commons` - Commons-specific protocol extensions
- `varint` - Variable-length integer encoding
- `economic` - Economic parameters and calculations
- `features` - Feature activation and management
- `validation` - Protocol-specific validation rules

### BIP Implementations
- `bip157` - Client-side block filtering (BIP157)
- `bip158` - Compact block filters (BIP158)
- `address` - Bech32/Bech32m address encoding (BIP173/350/351)
- `payment` - Payment protocol (BIP70)
- `fibre` - FIBRE protocol definitions

## Testing

```bash
# Run all tests
cargo test

# Run network message tests
cargo test --test network_message_tests

# Run protocol limits tests
cargo test --test protocol_limits_tests

# Run with specific protocol version
cargo test --features testnet

# Run with UTXO commitments
cargo test --features utxo-commitments
```

Test suite includes:
- Network message processing tests
- Protocol limits tests (DoS protection)
- BIP152 compact block relay tests
- Commons-specific message tests (UTXO commitments, filtered blocks, ban list)
- Error handling tests (malformed messages, protocol mismatches)
- Edge case tests (maximum sizes, boundary conditions)
- Service flags tests
- Varint encoding tests
- Protocol integration tests
- Validation rules tests
- Network parameters tests
- Feature registry tests
- BIP implementation tests

## Security Considerations

### Production Use
- **Mainnet**: Full consensus rules and security
- **Testnet**: Same rules as mainnet, different parameters
- **Regtest**: Relaxed rules for testing only

### Development Use
- **Regtest**: Safe for development and testing
- **Fast Mining**: Configurable difficulty for testing
- **Isolated**: No connection to real networks

### DoS Protection
- Protocol-level message size limits
- Address count limits
- Inventory item limits
- Header count limits
- Transaction count limits

## Dependencies

**Monorepo vs crates.io:** This repo’s `Cargo.toml` uses **path** dependencies for `blvm-consensus` when built next to sibling repos. For a crates.io-only dependency:

```toml
[dependencies]
blvm-protocol = "0.1.3"
```

`blvm-consensus` is pulled in transitively; ensure published versions match your crate’s `Cargo.toml` requirements.

All dependencies are pinned to exact versions for security. See `Cargo.toml` for the complete list.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [BTCDecoded Contribution Guide](https://github.com/BTCDecoded/.github/blob/main/CONTRIBUTING.md).
