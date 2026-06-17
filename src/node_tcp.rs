//! Bitcoin **TCP v1** framed messages: standard header (magic, command, length, checksum) plus payload.
//!
//! This is the full [`ProtocolMessage`] union and [`TcpFramedParser`] (parse/serialize) used by the
//! full node (`blvm-node`). **BIP324** v2 encrypted transport is the separate `v2_transport`
//! module (enable `feature = "bip324"`), not this stack.
//!
//! The embedding binary supplies which command strings are accepted (e.g. node `ALLOWED_COMMANDS`).

#[cfg(feature = "protocol-verification")]
use blvm_spec_lock::spec_locked;

use crate::wire::{
    deserialize_addrv2, deserialize_cmpctblock, deserialize_feefilter, deserialize_getblocks,
    deserialize_getdata, deserialize_getheaders, deserialize_headers, deserialize_inv,
    deserialize_notfound, deserialize_reject, deserialize_sendcmpct, deserialize_tx,
    serialize_addrv2, serialize_cmpctblock, serialize_feefilter, serialize_getblocks,
    serialize_getdata, serialize_getheaders, serialize_inv, serialize_notfound, serialize_reject,
    serialize_sendcmpct, serialize_tx,
};
use crate::{BlockHeader, Hash, Transaction};
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use crate::p2p_framing::{
    BITCOIN_MAGIC_MAINNET, BITCOIN_MAGIC_REGTEST, BITCOIN_MAGIC_TESTNET,
    BITCOIN_P2P_MAGIC_MAINNET_LE, MAX_ADDR_TO_SEND, MAX_HEADERS_RESULTS, MAX_INV_SZ,
    MAX_PROTOCOL_MESSAGE_LENGTH,
};

pub use crate::service_flags::commons::{
    NODE_BAN_LIST_SHARING, NODE_FIBRE, NODE_GOVERNANCE, NODE_PACKAGE_RELAY,
};

#[cfg(feature = "dandelion")]
pub use crate::service_flags::commons::NODE_DANDELION;

#[cfg(feature = "utxo-commitments")]
pub use crate::service_flags::commons::NODE_UTXO_COMMITMENTS;

#[cfg(feature = "erlay")]
pub use crate::service_flags::commons::NODE_ERLAY;

pub use crate::p2p_commands::cmd;

/// Bitcoin protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    Version(VersionMessage),
    Verack,
    Ping(PingMessage),
    Pong(PongMessage),
    GetHeaders(GetHeadersMessage),
    Headers(HeadersMessage),
    GetBlocks(GetBlocksMessage),
    Block(BlockMessage),
    GetData(GetDataMessage),
    Inv(InvMessage),
    NotFound(NotFoundMessage),
    /// BIP61 reject (informational)
    Reject(RejectMessage),
    Tx(TxMessage),
    /// BIP133 FeeFilter - peer's minimum fee rate for tx relay (we accept, no response)
    FeeFilter(FeeFilterMessage),
    /// Request for mempool tx announcements (empty payload)
    MemPool,
    /// BIP130 — prefer `headers` for block announcements (empty payload)
    SendHeaders,
    // Compact Block Relay (BIP152)
    SendCmpct(SendCmpctMessage),
    CmpctBlock(CompactBlockMessage),
    GetBlockTxn(GetBlockTxnMessage),
    BlockTxn(BlockTxnMessage),
    // UTXO commitment protocol extensions
    GetUTXOSet(GetUTXOSetMessage),
    UTXOSet(UTXOSetMessage),
    GetUTXOProof(GetUTXOProofMessage),
    UTXOProof(UTXOProofMessage),
    GetFilteredBlock(GetFilteredBlockMessage),
    FilteredBlock(FilteredBlockMessage),
    // Block Filtering (BIP157)
    GetCfilters(GetCfiltersMessage),
    Cfilter(CfilterMessage),
    GetCfheaders(GetCfheadersMessage),
    Cfheaders(CfheadersMessage),
    GetCfcheckpt(GetCfcheckptMessage),
    Cfcheckpt(CfcheckptMessage),
    // Payment Protocol (BIP70) - P2P variant
    GetPaymentRequest(GetPaymentRequestMessage),
    PaymentRequest(PaymentRequestMessage),
    Payment(PaymentMessage),
    PaymentACK(PaymentACKMessage),
    // CTV Payment Proof messages (for instant proof)
    #[cfg(feature = "ctv")]
    PaymentProof(PaymentProofMessage),
    SettlementNotification(SettlementNotificationMessage),
    // Package Relay (BIP 331)
    SendPkgTxn(SendPkgTxnMessage),
    PkgTxn(PkgTxnMessage),
    PkgTxnReject(PkgTxnRejectMessage),
    // Ban List Sharing
    GetBanList(GetBanListMessage),
    BanList(BanListMessage),
    // Mesh networking packets (payment-gated routing)
    MeshPacket(Vec<u8>), // Serialized mesh packet (handled by mesh module)
    // Address relay
    GetAddr,
    Addr(AddrMessage),
    /// BIP155 extended addresses
    AddrV2(AddrV2Message),
    // Module Registry
    GetModule(GetModuleMessage),
    Module(ModuleMessage),
    GetModuleByHash(GetModuleByHashMessage),
    ModuleByHash(ModuleByHashMessage),
    ModuleInv(ModuleInvMessage),
    GetModuleList(GetModuleListMessage),
    ModuleList(ModuleListMessage),
    /// Erlay (BIP330) — enable with `feature = "erlay"` on `blvm-protocol`.
    #[cfg(feature = "erlay")]
    SendTxRcncl(SendTxRcnclMessage),
    #[cfg(feature = "erlay")]
    ReqRecon(ReqReconMessage),
    #[cfg(feature = "erlay")]
    ReqSkt(ReqSktMessage),
    #[cfg(feature = "erlay")]
    Sketch(SketchMessage),
}

pub use crate::network::NetworkAddress;

// Pull shared types from blvm-protocol (single source of truth — field-identical to the
// former local definitions, so bincode wire format is preserved verbatim).
pub use crate::{
    BlockMessage, CompactBlockMessage, FilterPreferences, GetFilteredBlockMessage,
    GetUTXOProofMessage, GetUTXOSetMessage, TxMessage, UTXOCommitment, UTXOProofMessage,
    UTXOSetMessage,
};

/// Version message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

impl VersionMessage {
    /// Check if peer supports UTXO commitments
    #[cfg(feature = "utxo-commitments")]
    pub fn supports_utxo_commitments(&self) -> bool {
        (self.services & NODE_UTXO_COMMITMENTS) != 0
    }

    /// Check if peer supports ban list sharing
    pub fn supports_ban_list_sharing(&self) -> bool {
        (self.services & NODE_BAN_LIST_SHARING) != 0
    }

    /// Check if peer supports BIP157 compact block filters
    pub fn supports_compact_filters(&self) -> bool {
        use crate::bip157::NODE_COMPACT_FILTERS;
        (self.services & NODE_COMPACT_FILTERS) != 0
    }

    /// Check if peer supports package relay (BIP331)
    pub fn supports_package_relay(&self) -> bool {
        (self.services & NODE_PACKAGE_RELAY) != 0
    }

    /// Check if peer supports FIBRE
    pub fn supports_fibre(&self) -> bool {
        (self.services & NODE_FIBRE) != 0
    }

    #[cfg(feature = "dandelion")]
    /// Check if peer supports Dandelion
    pub fn supports_dandelion(&self) -> bool {
        (self.services & NODE_DANDELION) != 0
    }
}

// Re-export inventory and shared P2P payload types from blvm-protocol (single source of truth)
pub use crate::network::{
    AddrMessage, AddrV2Message, BlockTxnMessage, FeeFilterMessage, GetBlockTxnMessage,
    GetBlocksMessage, GetDataMessage, GetHeadersMessage, HeadersMessage, InvMessage,
    InventoryVector, NotFoundMessage, PingMessage, PongMessage, RejectMessage, SendCmpctMessage,
};

/// FilteredBlock message - Response with filtered transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteredBlockMessage {
    /// Request ID (echo from GetFilteredBlock for matching)
    pub request_id: u64,
    /// Block header
    pub header: BlockHeader,
    /// UTXO commitment for this block
    pub commitment: UTXOCommitment,
    /// Filtered transactions (only non-spam)
    pub transactions: Vec<Transaction>,
    /// Transaction indices in original block (for verification)
    pub transaction_indices: Vec<u32>,
    /// Summary of filtered spam
    pub spam_summary: SpamSummary,
    /// Optional BIP158 compact block filter (if requested and available)
    ///
    /// This allows clients to get both spam-filtered transactions (UTXO commitments)
    /// and BIP158 filters (light client discovery) in a single response.
    /// When present, clients can use the filter for efficient transaction matching
    /// while still receiving the commitment data for verification.
    pub bip158_filter: Option<Bip158FilterData>,
}

/// BIP158 filter data (embedded in FilteredBlock message)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip158FilterData {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Compact block filter data
    pub filter_data: Vec<u8>,
    /// Number of elements in filter
    pub num_elements: u32,
}

// Block Filtering (BIP157) messages

/// getcfilters message - Request filters for block range
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetCfiltersMessage {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Start block height
    pub start_height: u32,
    /// Stop block hash
    pub stop_hash: Hash,
}

/// cfilter message - Compact block filter response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfilterMessage {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Block hash
    pub block_hash: Hash,
    /// Compact block filter data
    pub filter_data: Vec<u8>,
    /// Number of elements in filter
    pub num_elements: u32,
}

/// getcfheaders message - Request filter headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCfheadersMessage {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Start block height
    pub start_height: u32,
    /// Stop block hash
    pub stop_hash: Hash,
}

/// cfheaders message - Filter headers response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfheadersMessage {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Stop block hash
    pub stop_hash: Hash,
    /// Previous filter header
    pub prev_header: FilterHeaderData,
    /// Filter headers (one per block in range)
    pub filter_headers: Vec<Hash>,
}

/// Filter header data (for serialization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterHeaderData {
    /// Filter hash
    pub filter_hash: Hash,
    /// Previous filter header hash
    pub prev_header_hash: Hash,
}

/// getcfcheckpt message - Request filter checkpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCfcheckptMessage {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Stop block hash
    pub stop_hash: Hash,
}

/// cfcheckpt message - Filter checkpoint response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfcheckptMessage {
    /// Filter type (0 = Basic)
    pub filter_type: u8,
    /// Stop block hash
    pub stop_hash: Hash,
    /// Filter header hashes at checkpoint intervals
    pub filter_header_hashes: Vec<Hash>,
}

// Payment Protocol (BIP70) - P2P variant messages

/// getpaymentrequest message - Request payment details from merchant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPaymentRequestMessage {
    /// Merchant's Bitcoin public key (compressed, 33 bytes)
    #[serde(with = "serde_bytes")]
    pub merchant_pubkey: Vec<u8>,
    /// Unique payment identifier (32-byte hash)
    #[serde(with = "serde_bytes")]
    pub payment_id: Vec<u8>,
    /// Network identifier ("main", "test", "regtest")
    pub network: String,
}

/// paymentrequest message - Merchant payment request response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequestMessage {
    /// Payment request details (from bip70 module)
    pub payment_request: crate::payment::PaymentRequest,
    /// Signature over payment_request by merchant's Bitcoin key
    #[serde(with = "serde_bytes")]
    pub merchant_signature: Vec<u8>,
    /// Merchant's public key (compressed, 33 bytes)
    #[serde(with = "serde_bytes")]
    pub merchant_pubkey: Vec<u8>,
    /// Payment ID (echo from GetPaymentRequest)
    #[serde(with = "serde_bytes")]
    pub payment_id: Vec<u8>,
    /// Optional CTV covenant proof (for instant proof)
    #[cfg(feature = "ctv")]
    #[serde(default)]
    pub covenant_proof: Option<crate::payment::CovenantProof>,
}

/// payment message - Customer payment transaction(s)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMessage {
    /// Payment details (from payment protocol module)
    pub payment: crate::payment::Payment,
    /// Payment ID (echo from PaymentRequest)
    #[serde(with = "serde_bytes")]
    pub payment_id: Vec<u8>,
    /// Optional customer signature (for authenticated payments)
    #[serde(with = "serde_bytes")]
    pub customer_signature: Option<Vec<u8>>,
}

/// paymentack message - Merchant payment confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentACKMessage {
    /// Payment acknowledgment (from payment protocol module)
    pub payment_ack: crate::payment::PaymentACK,
    /// Payment ID (echo from Payment)
    #[serde(with = "serde_bytes")]
    pub payment_id: Vec<u8>,
    /// Merchant signature confirming receipt
    #[serde(with = "serde_bytes")]
    pub merchant_signature: Vec<u8>,
}

// CTV Payment Proof messages (for instant proof, not instant settlement)

/// paymentproof message - CTV covenant proof for payment commitment
#[cfg(feature = "ctv")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProofMessage {
    /// Request ID for async request-response matching
    pub request_id: u64,
    /// Payment request ID this proof commits to
    pub payment_request_id: String,
    /// CTV covenant proof
    pub covenant_proof: crate::payment::CovenantProof,
    /// Optional full transaction template (for verification)
    pub transaction_template: Option<crate::payment::TransactionTemplate>,
}

/// settlementnotification message - Settlement status update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementNotificationMessage {
    /// Payment request ID
    pub payment_request_id: String,
    /// Transaction hash (if in mempool or confirmed)
    pub transaction_hash: Option<Hash>,
    /// Confirmation count (0 = in mempool, >0 = confirmed)
    pub confirmation_count: u32,
    /// Block hash (if confirmed)
    pub block_hash: Option<Hash>,
    /// Settlement status
    pub status: String, // "mempool", "confirmed", "failed"
}

// Package Relay (BIP 331) messages

/// sendpkgtxn message - Request to send package of transactions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendPkgTxnMessage {
    /// Package ID (combined hash of all transactions)
    #[serde(with = "serde_bytes")]
    pub package_id: Vec<u8>,
    /// Transaction hashes in package (ordered: parents first)
    pub tx_hashes: Vec<Hash>,
}

/// pkgtxn message - Package of transactions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkgTxnMessage {
    /// Package ID (echo from SendPkgTxn)
    #[serde(with = "serde_bytes")]
    pub package_id: Vec<u8>,
    /// Transactions in package (ordered: parents first)
    /// Using Vec<u8> for serialized transactions (matches BIP 331 spec)
    pub transactions: Vec<Vec<u8>>,
}

/// pkgtxnreject message - Package rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgTxnRejectMessage {
    /// Package ID that was rejected
    #[serde(with = "serde_bytes")]
    pub package_id: Vec<u8>,
    /// Rejection reason code
    pub reason: u8,
    /// Optional rejection reason text
    pub reason_text: Option<String>,
}

// Module Registry messages

/// getmodule message - Request module by name
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetModuleMessage {
    /// Request ID for async request-response matching
    pub request_id: u64,
    /// Module name
    pub name: String,
    /// Optional version (if not specified, get latest)
    pub version: Option<String>,
    /// Optional payment ID (required if module requires payment)
    /// This is the payment_id from a completed PaymentACK
    pub payment_id: Option<String>,
}

/// module message - Module response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMessage {
    /// Request ID (echo from GetModule for matching)
    pub request_id: u64,
    /// Module name
    pub name: String,
    /// Module version
    pub version: String,
    /// Module hash (content-addressable identifier)
    pub hash: Hash,
    /// Manifest hash
    pub manifest_hash: Hash,
    /// Binary hash
    pub binary_hash: Hash,
    /// Manifest content (TOML)
    pub manifest: Vec<u8>,
    /// Binary content (optional - may be fetched separately via getmodulebyhash)
    pub binary: Option<Vec<u8>>,
}

/// getmodulebyhash message - Request module by hash (content-addressable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetModuleByHashMessage {
    /// Request ID for async request-response matching
    pub request_id: u64,
    /// Module hash
    pub hash: Hash,
    /// Request binary (if false, only manifest is returned)
    pub include_binary: bool,
}

/// modulebyhash message - Module response by hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleByHashMessage {
    /// Request ID (echo from GetModuleByHash for matching)
    pub request_id: u64,
    /// Module hash (echo from request)
    pub hash: Hash,
    /// Manifest content
    pub manifest: Vec<u8>,
    /// Binary content (if requested)
    pub binary: Option<Vec<u8>>,
}

/// moduleinv message - Module inventory (announce available modules)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInvMessage {
    /// List of available modules
    pub modules: Vec<ModuleInventoryItem>,
}

/// Module inventory item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInventoryItem {
    /// Module name
    pub name: String,
    /// Module version
    pub version: String,
    /// Module hash
    pub hash: Hash,
}

/// getmodulelist message - Request list of available modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetModuleListMessage {
    /// Optional filter by name prefix
    pub name_prefix: Option<String>,
    /// Maximum number of modules to return
    pub max_count: Option<u32>,
}

/// modulelist message - List of available modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleListMessage {
    /// List of available modules
    pub modules: Vec<ModuleInventoryItem>,
}

// Erlay (BIP330) transaction relay messages

/// sendtxrcncl message - Announce Erlay support and negotiate parameters
#[cfg(feature = "erlay")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendTxRcnclMessage {
    /// Erlay version (currently 1)
    pub version: u16,
    /// Initial reconciliation salt (for privacy)
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 16],
    /// Minimum field size in bits (32 or 64)
    pub min_field_size: u8,
    /// Maximum field size in bits (32 or 64)
    pub max_field_size: u8,
}

/// reqrecon message - Request reconciliation
#[cfg(feature = "erlay")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReqReconMessage {
    /// Reconciliation salt (for privacy)
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 16],
    /// Local transaction set size
    pub local_set_size: u32,
    /// Field size in bits (32 or 64)
    pub field_size: u8,
}

/// reqskt message - Request sketch
#[cfg(feature = "erlay")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReqSktMessage {
    /// Reconciliation salt (echo from ReqRecon)
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 16],
    /// Remote transaction set size
    pub remote_set_size: u32,
    /// Field size in bits (32 or 64)
    pub field_size: u8,
}

/// sketch message - Send reconciliation sketch
#[cfg(feature = "erlay")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SketchMessage {
    /// Reconciliation salt (echo from ReqRecon)
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 16],
    /// Reconciliation sketch (minisketch serialized data)
    #[serde(with = "serde_bytes")]
    pub sketch: Vec<u8>,
    /// Field size in bits (32 or 64)
    pub field_size: u8,
}

/// SpamSummary - Summary of filtered spam transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamSummary {
    /// Number of transactions filtered
    pub filtered_count: u32,
    /// Total size of filtered transactions (bytes)
    pub filtered_size: u64,
    /// Breakdown by spam type
    pub by_type: SpamBreakdown,
}

/// SpamBreakdown - Breakdown of spam by category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamBreakdown {
    pub ordinals: u32,
    pub inscriptions: u32,
    pub dust: u32,
    pub brc20: u32,
}

/// Bitcoin P2P framed message parser (TCP path). Pass allowed commands from the node.
pub struct TcpFramedParser;

impl TcpFramedParser {
    /// Parse a raw message into a protocol message
    /// Orange Paper 10.1.1: ParseMessage, size bounds, checksum rejection
    #[cfg_attr(
        feature = "protocol-verification",
        spec_locked("10.1.1", "ParseMessage")
    )]
    #[cfg_attr(
        feature = "protocol-verification",
        blvm_spec_lock::ensures(data.len() >= 24 || result.is_err())
    )]
    pub fn parse_message(data: &[u8], allowed_commands: &[&str]) -> Result<ProtocolMessage> {
        use tracing::{debug, warn};

        if data.len() >= 4 {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            debug!(
                "Parsing message: magic=0x{:08x}, total_len={}",
                magic,
                data.len()
            );
            if magic != BITCOIN_P2P_MAGIC_MAINNET_LE {
                let header_hex: String = data.iter().take(24).map(|b| format!("{b:02x}")).collect();
                warn!(
                    "Invalid magic number 0x{:08x}, expected 0x{:08x}. Header hex: {}",
                    magic, BITCOIN_P2P_MAGIC_MAINNET_LE, header_hex
                );
            }
        }

        let (command, payload) =
            crate::p2p_frame::parse_p2p_frame(data, BITCOIN_P2P_MAGIC_MAINNET_LE, |c| {
                allowed_commands.contains(&c)
            })
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        debug!("Message command: '{}', data_len={}", command, data.len());

        // Parse payload based on command
        match command {
            cmd::VERSION => {
                // Use proper Bitcoin wire format deserialization for version messages
                use crate::wire::deserialize_version;

                let version_msg = deserialize_version(payload)?;

                Ok(ProtocolMessage::Version(VersionMessage {
                    version: version_msg.version as i32, // blvm-node uses i32, blvm-protocol uses u32
                    services: version_msg.services,
                    timestamp: version_msg.timestamp,
                    addr_recv: version_msg.addr_recv,
                    addr_from: version_msg.addr_from,
                    nonce: version_msg.nonce,
                    user_agent: version_msg.user_agent,
                    start_height: version_msg.start_height,
                    relay: version_msg.relay,
                }))
            }
            cmd::VERACK => Ok(ProtocolMessage::Verack),
            cmd::SENDHEADERS => Ok(ProtocolMessage::SendHeaders),
            cmd::PING => {
                // Use proper Bitcoin wire format (8-byte nonce)
                let wire_msg = crate::wire::deserialize_ping(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize ping: {}", e))?;
                Ok(ProtocolMessage::Ping(PingMessage {
                    nonce: wire_msg.nonce,
                }))
            }
            cmd::PONG => {
                // Use proper Bitcoin wire format (8-byte nonce)
                let wire_msg = crate::wire::deserialize_pong(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize pong: {}", e))?;
                Ok(ProtocolMessage::Pong(PongMessage {
                    nonce: wire_msg.nonce,
                }))
            }
            cmd::GETHEADERS => {
                let wire_msg = deserialize_getheaders(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize getheaders: {}", e))?;
                Ok(ProtocolMessage::GetHeaders(wire_msg))
            }
            cmd::HEADERS => {
                let wire_msg = deserialize_headers(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize headers: {}", e))?;
                Ok(ProtocolMessage::Headers(wire_msg))
            }
            cmd::GETBLOCKS => {
                let wire_msg = deserialize_getblocks(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize getblocks: {}", e))?;
                Ok(ProtocolMessage::GetBlocks(wire_msg))
            }
            cmd::BLOCK => {
                // Use consensus wire format (Bitcoin block + witness structure)
                let (block, witnesses) =
                    crate::serialization::deserialize_block_with_witnesses(payload)
                        .map_err(|e| anyhow::anyhow!("Failed to deserialize block: {}", e))?;
                Ok(ProtocolMessage::Block(BlockMessage { block, witnesses }))
            }
            cmd::GETDATA => {
                let msg = deserialize_getdata(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize getdata: {}", e))?;
                Ok(ProtocolMessage::GetData(msg))
            }
            cmd::INV => {
                let msg = deserialize_inv(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize inv: {}", e))?;
                Ok(ProtocolMessage::Inv(msg))
            }
            cmd::NOTFOUND => {
                let msg = deserialize_notfound(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize notfound: {}", e))?;
                Ok(ProtocolMessage::NotFound(msg))
            }
            cmd::REJECT => {
                let msg = deserialize_reject(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize reject: {}", e))?;
                Ok(ProtocolMessage::Reject(msg))
            }
            cmd::TX => {
                let transaction = deserialize_tx(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize tx: {}", e))?;
                Ok(ProtocolMessage::Tx(TxMessage { transaction }))
            }
            cmd::MEMPOOL => Ok(ProtocolMessage::MemPool),
            cmd::FEEFILTER => {
                let msg = deserialize_feefilter(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize feefilter: {}", e))?;
                Ok(ProtocolMessage::FeeFilter(msg))
            }
            // Compact Block Relay (BIP152)
            cmd::SENDCMPCT => {
                let msg = deserialize_sendcmpct(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize sendcmpct: {}", e))?;
                Ok(ProtocolMessage::SendCmpct(msg))
            }
            cmd::CMPCTBLOCK => {
                let wire_msg = deserialize_cmpctblock(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize cmpctblock: {}", e))?;
                let compact_block = crate::bip152::CompactBlock::from(&wire_msg);
                Ok(ProtocolMessage::CmpctBlock(CompactBlockMessage {
                    compact_block,
                }))
            }
            cmd::GETBLOCKTXN => {
                let wire_msg = crate::wire::deserialize_getblocktxn(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize getblocktxn: {}", e))?;
                Ok(ProtocolMessage::GetBlockTxn(wire_msg))
            }
            cmd::BLOCKTXN => {
                let wire_msg = crate::wire::deserialize_blocktxn(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize blocktxn: {}", e))?;
                Ok(ProtocolMessage::BlockTxn(wire_msg))
            }
            // UTXO commitment protocol extensions
            cmd::GETUTXOSET => Ok(ProtocolMessage::GetUTXOSet(bincode::deserialize(payload)?)),
            cmd::UTXOSET => Ok(ProtocolMessage::UTXOSet(bincode::deserialize(payload)?)),
            cmd::GETUTXOPROOF => Ok(ProtocolMessage::GetUTXOProof(bincode::deserialize(
                payload,
            )?)),
            cmd::UTXOPROOF => Ok(ProtocolMessage::UTXOProof(bincode::deserialize(payload)?)),
            cmd::GETFILTEREDBLOCK => Ok(ProtocolMessage::GetFilteredBlock(bincode::deserialize(
                payload,
            )?)),
            cmd::FILTEREDBLOCK => Ok(ProtocolMessage::FilteredBlock(bincode::deserialize(
                payload,
            )?)),
            // Block Filtering (BIP157)
            cmd::GETCFILTERS => Ok(ProtocolMessage::GetCfilters(bincode::deserialize(payload)?)),
            cmd::CFILTER => Ok(ProtocolMessage::Cfilter(bincode::deserialize(payload)?)),
            cmd::GETCFHEADERS => Ok(ProtocolMessage::GetCfheaders(bincode::deserialize(
                payload,
            )?)),
            cmd::CFHEADERS => Ok(ProtocolMessage::Cfheaders(bincode::deserialize(payload)?)),
            cmd::GETCFCHECKPT => Ok(ProtocolMessage::GetCfcheckpt(bincode::deserialize(
                payload,
            )?)),
            cmd::CFCHECKPT => Ok(ProtocolMessage::Cfcheckpt(bincode::deserialize(payload)?)),
            // Payment Protocol (BIP70) - P2P variant
            cmd::GETPAYMENTREQUEST => Ok(ProtocolMessage::GetPaymentRequest(bincode::deserialize(
                payload,
            )?)),
            cmd::PAYMENTREQUEST => Ok(ProtocolMessage::PaymentRequest(bincode::deserialize(
                payload,
            )?)),
            cmd::PAYMENT => Ok(ProtocolMessage::Payment(bincode::deserialize(payload)?)),
            cmd::PAYMENTACK => Ok(ProtocolMessage::PaymentACK(bincode::deserialize(payload)?)),
            #[cfg(feature = "ctv")]
            cmd::PAYMENTPROOF => Ok(ProtocolMessage::PaymentProof(bincode::deserialize(
                payload,
            )?)),
            cmd::SETTLEMENTNOTIFICATION => Ok(ProtocolMessage::SettlementNotification(
                bincode::deserialize(payload)?,
            )),
            // Package Relay (BIP 331)
            cmd::SENDPKGTXN => Ok(ProtocolMessage::SendPkgTxn(bincode::deserialize(payload)?)),
            cmd::PKGTXN => Ok(ProtocolMessage::PkgTxn(bincode::deserialize(payload)?)),
            cmd::PKGTXNREJECT => Ok(ProtocolMessage::PkgTxnReject(bincode::deserialize(
                payload,
            )?)),
            // Ban List Sharing
            cmd::GETBANLIST => Ok(ProtocolMessage::GetBanList(bincode::deserialize(payload)?)),
            cmd::BANLIST => Ok(ProtocolMessage::BanList(bincode::deserialize(payload)?)),
            cmd::GETADDR => Ok(ProtocolMessage::GetAddr),
            cmd::ADDR => {
                let wire_msg = crate::wire::deserialize_addr(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize addr: {}", e))?;
                Ok(ProtocolMessage::Addr(wire_msg))
            }
            cmd::ADDRV2 => {
                let wire_msg = deserialize_addrv2(payload)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize addrv2: {}", e))?;
                Ok(ProtocolMessage::AddrV2(wire_msg))
            }
            // Module Registry
            cmd::GETMODULE => Ok(ProtocolMessage::GetModule(bincode::deserialize(payload)?)),
            cmd::MODULE => Ok(ProtocolMessage::Module(bincode::deserialize(payload)?)),
            cmd::GETMODULEBYHASH => Ok(ProtocolMessage::GetModuleByHash(bincode::deserialize(
                payload,
            )?)),
            cmd::MODULEBYHASH => Ok(ProtocolMessage::ModuleByHash(bincode::deserialize(
                payload,
            )?)),
            cmd::MODULEINV => Ok(ProtocolMessage::ModuleInv(bincode::deserialize(payload)?)),
            cmd::GETMODULELIST => Ok(ProtocolMessage::GetModuleList(bincode::deserialize(
                payload,
            )?)),
            cmd::MODULELIST => Ok(ProtocolMessage::ModuleList(bincode::deserialize(payload)?)),
            // Mesh networking packets
            cmd::MESH => Ok(ProtocolMessage::MeshPacket(payload.to_vec())),
            #[cfg(feature = "erlay")]
            cmd::SENDTXRCNCL => Ok(ProtocolMessage::SendTxRcncl(bincode::deserialize(payload)?)),
            #[cfg(feature = "erlay")]
            cmd::REQRECON => Ok(ProtocolMessage::ReqRecon(bincode::deserialize(payload)?)),
            #[cfg(feature = "erlay")]
            cmd::REQSKT => Ok(ProtocolMessage::ReqSkt(bincode::deserialize(payload)?)),
            #[cfg(feature = "erlay")]
            cmd::SKETCH => Ok(ProtocolMessage::Sketch(bincode::deserialize(payload)?)),
            _ => Err(anyhow::anyhow!("Unknown command: {}", command)),
        }
    }

    /// Serialize a protocol message to bytes
    pub fn serialize_message(message: &ProtocolMessage) -> Result<Vec<u8>> {
        let (command, payload) = match message {
            ProtocolMessage::Version(msg) => {
                // Use proper Bitcoin wire format for version messages
                use crate::network::VersionMessage as WireVersionMessage;
                use crate::wire::serialize_version;

                let version_msg = WireVersionMessage {
                    version: msg.version as u32,
                    services: msg.services,
                    timestamp: msg.timestamp,
                    addr_recv: msg.addr_recv.clone(),
                    addr_from: msg.addr_from.clone(),
                    nonce: msg.nonce,
                    user_agent: msg.user_agent.clone(),
                    start_height: msg.start_height,
                    relay: msg.relay,
                };

                // Serialize payload using proper Bitcoin wire format
                // This uses the serialize_version function from blvm-protocol wire.rs
                // which implements the exact Bitcoin protocol format
                let payload = serialize_version(&version_msg)?;
                (cmd::VERSION, payload)
            }
            ProtocolMessage::Verack => (cmd::VERACK, vec![]),
            ProtocolMessage::SendHeaders => (cmd::SENDHEADERS, vec![]),
            ProtocolMessage::Ping(msg) => (
                cmd::PING,
                crate::wire::serialize_ping(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::Pong(msg) => (
                cmd::PONG,
                crate::wire::serialize_pong(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::GetHeaders(msg) => (
                cmd::GETHEADERS,
                serialize_getheaders(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::Headers(msg) => (
                cmd::HEADERS,
                crate::wire::serialize_headers(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::GetBlocks(msg) => (
                cmd::GETBLOCKS,
                serialize_getblocks(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::Block(msg) => {
                // Must match `parse_message` cmd::BLOCK: consensus block+witness wire bytes, not bincode.
                let payload = crate::serialization::serialize_block_with_witnesses(
                    &msg.block,
                    &msg.witnesses,
                    true,
                );
                (cmd::BLOCK, payload)
            }
            ProtocolMessage::GetData(msg) => (
                cmd::GETDATA,
                serialize_getdata(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::Inv(msg) => (
                cmd::INV,
                serialize_inv(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::NotFound(msg) => (
                cmd::NOTFOUND,
                serialize_notfound(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::Reject(msg) => (
                cmd::REJECT,
                serialize_reject(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::Tx(msg) => (
                cmd::TX,
                serialize_tx(&msg.transaction).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::FeeFilter(msg) => (
                cmd::FEEFILTER,
                serialize_feefilter(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::MemPool => (cmd::MEMPOOL, vec![]),
            // Compact Block Relay (BIP152)
            ProtocolMessage::SendCmpct(msg) => (
                cmd::SENDCMPCT,
                serialize_sendcmpct(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::CmpctBlock(msg) => {
                use crate::network::CmpctBlockMessage;
                let wire_msg = CmpctBlockMessage::try_from(msg.compact_block.clone())
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let payload =
                    serialize_cmpctblock(&wire_msg).map_err(|e| anyhow::anyhow!("{}", e))?;
                (cmd::CMPCTBLOCK, payload)
            }
            ProtocolMessage::GetBlockTxn(msg) => (
                cmd::GETBLOCKTXN,
                crate::wire::serialize_getblocktxn(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::BlockTxn(msg) => (
                cmd::BLOCKTXN,
                crate::wire::serialize_blocktxn(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            // UTXO commitment protocol extensions
            ProtocolMessage::GetUTXOSet(msg) => (cmd::GETUTXOSET, bincode::serialize(msg)?),
            ProtocolMessage::UTXOSet(msg) => (cmd::UTXOSET, bincode::serialize(msg)?),
            ProtocolMessage::GetUTXOProof(msg) => (cmd::GETUTXOPROOF, bincode::serialize(msg)?),
            ProtocolMessage::UTXOProof(msg) => (cmd::UTXOPROOF, bincode::serialize(msg)?),
            ProtocolMessage::GetFilteredBlock(msg) => {
                (cmd::GETFILTEREDBLOCK, bincode::serialize(msg)?)
            }
            ProtocolMessage::FilteredBlock(msg) => (cmd::FILTEREDBLOCK, bincode::serialize(msg)?),
            // Block Filtering (BIP157)
            ProtocolMessage::GetCfilters(msg) => (cmd::GETCFILTERS, bincode::serialize(msg)?),
            ProtocolMessage::Cfilter(msg) => (cmd::CFILTER, bincode::serialize(msg)?),
            ProtocolMessage::GetCfheaders(msg) => (cmd::GETCFHEADERS, bincode::serialize(msg)?),
            ProtocolMessage::Cfheaders(msg) => (cmd::CFHEADERS, bincode::serialize(msg)?),
            ProtocolMessage::GetCfcheckpt(msg) => (cmd::GETCFCHECKPT, bincode::serialize(msg)?),
            ProtocolMessage::Cfcheckpt(msg) => (cmd::CFCHECKPT, bincode::serialize(msg)?),
            // Payment Protocol (BIP70) - P2P variant
            ProtocolMessage::GetPaymentRequest(msg) => {
                (cmd::GETPAYMENTREQUEST, bincode::serialize(msg)?)
            }
            ProtocolMessage::PaymentRequest(msg) => (cmd::PAYMENTREQUEST, bincode::serialize(msg)?),
            ProtocolMessage::Payment(msg) => (cmd::PAYMENT, bincode::serialize(msg)?),
            ProtocolMessage::PaymentACK(msg) => (cmd::PAYMENTACK, bincode::serialize(msg)?),
            // CTV Payment Proof messages
            #[cfg(feature = "ctv")]
            ProtocolMessage::PaymentProof(msg) => (cmd::PAYMENTPROOF, bincode::serialize(msg)?),
            ProtocolMessage::SettlementNotification(msg) => {
                (cmd::SETTLEMENTNOTIFICATION, bincode::serialize(msg)?)
            }
            // Package Relay (BIP 331)
            ProtocolMessage::SendPkgTxn(msg) => (cmd::SENDPKGTXN, bincode::serialize(msg)?),
            ProtocolMessage::PkgTxn(msg) => (cmd::PKGTXN, bincode::serialize(msg)?),
            ProtocolMessage::PkgTxnReject(msg) => (cmd::PKGTXNREJECT, bincode::serialize(msg)?),
            // Ban List Sharing
            ProtocolMessage::GetBanList(msg) => (cmd::GETBANLIST, bincode::serialize(msg)?),
            ProtocolMessage::BanList(msg) => (cmd::BANLIST, bincode::serialize(msg)?),
            // Address relay
            ProtocolMessage::GetAddr => (cmd::GETADDR, vec![]),
            ProtocolMessage::Addr(msg) => (
                cmd::ADDR,
                crate::wire::serialize_addr(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            ProtocolMessage::AddrV2(msg) => (
                cmd::ADDRV2,
                serialize_addrv2(msg).map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            // Module Registry
            ProtocolMessage::GetModule(msg) => (cmd::GETMODULE, bincode::serialize(msg)?),
            ProtocolMessage::Module(msg) => (cmd::MODULE, bincode::serialize(msg)?),
            ProtocolMessage::GetModuleByHash(msg) => {
                (cmd::GETMODULEBYHASH, bincode::serialize(msg)?)
            }
            ProtocolMessage::ModuleByHash(msg) => (cmd::MODULEBYHASH, bincode::serialize(msg)?),
            ProtocolMessage::ModuleInv(msg) => (cmd::MODULEINV, bincode::serialize(msg)?),
            ProtocolMessage::GetModuleList(msg) => (cmd::GETMODULELIST, bincode::serialize(msg)?),
            ProtocolMessage::ModuleList(msg) => (cmd::MODULELIST, bincode::serialize(msg)?),
            ProtocolMessage::MeshPacket(_) => {
                return Err(anyhow::anyhow!("MeshPacket handled separately"));
            }
            #[cfg(feature = "erlay")]
            ProtocolMessage::SendTxRcncl(msg) => (cmd::SENDTXRCNCL, bincode::serialize(msg)?),
            #[cfg(feature = "erlay")]
            ProtocolMessage::ReqRecon(msg) => (cmd::REQRECON, bincode::serialize(msg)?),
            #[cfg(feature = "erlay")]
            ProtocolMessage::ReqSkt(msg) => (cmd::REQSKT, bincode::serialize(msg)?),
            #[cfg(feature = "erlay")]
            ProtocolMessage::Sketch(msg) => (cmd::SKETCH, bincode::serialize(msg)?),
        };

        crate::p2p_frame::build_p2p_frame(BITCOIN_MAGIC_MAINNET, command, &payload)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Calculate message checksum
    ///
    /// Computes double SHA256 of payload and returns first 4 bytes.
    /// Orange Paper 10.1.1: CalculateChecksum, |result| = 4
    #[cfg_attr(
        feature = "protocol-verification",
        spec_locked("10.1.1", "CalculateChecksum")
    )]
    #[cfg_attr(
        feature = "protocol-verification",
        blvm_spec_lock::ensures(result.len() == 4)
    )]
    pub fn calculate_checksum(payload: &[u8]) -> [u8; 4] {
        crate::p2p_frame::bitcoin_p2p_payload_checksum(payload)
    }
}

// Ban List Sharing messages

/// GetBanList message - Request peer's ban list (or hashed version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBanListMessage {
    /// Request full ban list (true) or just hash (false)
    pub request_full: bool,
    /// Minimum ban duration to include (seconds, 0 = all)
    pub min_ban_duration: u64,
}

/// BanList message - Response with ban list or hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanListMessage {
    /// If false, only ban_list_hash is valid
    pub is_full: bool,
    /// Hash of full ban list (SHA256 of sorted entries)
    pub ban_list_hash: Hash,
    /// Full ban list entries (only if is_full = true)
    pub ban_entries: Vec<BanEntry>,
    /// Timestamp when ban list was generated
    pub timestamp: u64,
}

/// Single ban entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    /// Banned peer address
    pub addr: NetworkAddress,
    /// Unix timestamp when ban expires (u64::MAX = permanent)
    pub unban_timestamp: u64,
    /// Reason for ban (optional)
    pub reason: Option<String>,
}
