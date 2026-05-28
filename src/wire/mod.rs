//! Bitcoin P2P wire format serialization
//!
//! Implements Bitcoin P2P protocol message framing:
//! Format: [magic:4][command:12][length:4][checksum:4][payload:var]
//!
//! - Magic bytes: Network identifier (mainnet, testnet, etc.)
//! - Command: 12-byte ASCII string (null-padded)
//! - Length: Payload length in bytes (little-endian u32)
//! - Checksum: First 4 bytes of double SHA256 of payload
//! - Payload: Message-specific data

use crate::error::ProtocolError;
use crate::network::NetworkMessage;
use crate::ConsensusError;
use crate::Result;
use std::borrow::Cow;
use std::io::Read;
use std::sync::Arc;

mod frame_header;
pub use frame_header::{calculate_checksum, MAX_MESSAGE_PAYLOAD, MESSAGE_HEADER_SIZE};

/// Serialize a network message to Bitcoin P2P wire format
pub fn serialize_message(message: &NetworkMessage, magic_bytes: [u8; 4]) -> Result<Vec<u8>> {
    use crate::network::*;

    // Serialize payload based on message type
    let (command, payload) = match message {
        NetworkMessage::Version(v) => ("version", serialize_version(v)?),
        NetworkMessage::VerAck => ("verack", vec![]),
        NetworkMessage::Addr(a) => ("addr", serialize_addr(a)?),
        NetworkMessage::AddrV2(a) => ("addrv2", serialize_addrv2(a)?),
        NetworkMessage::Inv(i) => ("inv", serialize_inv(i)?),
        NetworkMessage::GetData(g) => ("getdata", serialize_getdata(g)?),
        NetworkMessage::GetHeaders(gh) => ("getheaders", serialize_getheaders(gh)?),
        NetworkMessage::Headers(h) => ("headers", serialize_headers(h)?),
        NetworkMessage::Block(b, witnesses) => ("block", serialize_block_witnesses(b, witnesses)?),
        NetworkMessage::Tx(tx) => ("tx", serialize_tx(tx)?),
        NetworkMessage::Ping(p) => ("ping", serialize_ping(p)?),
        NetworkMessage::Pong(p) => ("pong", serialize_pong(p)?),
        NetworkMessage::MemPool => ("mempool", vec![]),
        NetworkMessage::FeeFilter(f) => ("feefilter", serialize_feefilter(f)?),
        NetworkMessage::GetBlocks(gb) => ("getblocks", serialize_getblocks(gb)?),
        NetworkMessage::GetAddr => ("getaddr", vec![]),
        NetworkMessage::NotFound(nf) => ("notfound", serialize_notfound(nf)?),
        NetworkMessage::Reject(r) => ("reject", serialize_reject(r)?),
        NetworkMessage::SendHeaders => ("sendheaders", vec![]),
        NetworkMessage::SendCmpct(sc) => ("sendcmpct", serialize_sendcmpct(sc)?),
        NetworkMessage::CmpctBlock(cb) => ("cmpctblock", serialize_cmpctblock(cb)?),
        NetworkMessage::GetBlockTxn(gbt) => ("getblocktxn", serialize_getblocktxn(gbt)?),
        NetworkMessage::BlockTxn(bt) => ("blocktxn", serialize_blocktxn(bt)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::GetUTXOSet(gus) => ("getutxoset", serialize_getutxoset(gus)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::UTXOSet(us) => ("utxoset", serialize_utxoset(us)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::GetFilteredBlock(gfb) => {
            ("getfilteredblock", serialize_getfilteredblock(gfb)?)
        }
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::FilteredBlock(fb) => ("filteredblock", serialize_filteredblock(fb)?),
        NetworkMessage::GetBanList(gbl) => ("getbanlist", serialize_getbanlist(gbl)?),
        NetworkMessage::BanList(bl) => ("banlist", serialize_banlist(bl)?),
    };

    // Validate payload size
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!(
                "Message payload too large: {} bytes",
                payload.len()
            )),
        )));
    }

    // Calculate checksum
    let checksum = calculate_checksum(&payload);

    // Build message
    let mut message_bytes = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len());

    // Magic bytes
    message_bytes.extend_from_slice(&magic_bytes);

    // Command (12 bytes, null-padded)
    let mut command_bytes = [0u8; 12];
    let cmd_len = command.len().min(12);
    command_bytes[..cmd_len].copy_from_slice(&command.as_bytes()[..cmd_len]);
    message_bytes.extend_from_slice(&command_bytes);

    // Payload length (little-endian u32)
    message_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());

    // Checksum
    message_bytes.extend_from_slice(&checksum);

    // Payload
    message_bytes.extend_from_slice(&payload);

    Ok(message_bytes)
}

/// Deserialize Bitcoin P2P wire format to network message
pub fn deserialize_message<R: Read>(
    reader: &mut R,
    expected_magic: [u8; 4],
) -> Result<(NetworkMessage, usize)> {
    use crate::network::*;

    // Read header
    let mut header = [0u8; MESSAGE_HEADER_SIZE];
    reader.read_exact(&mut header).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "IO error: {e}"
        ))))
    })?;

    // Check magic bytes
    let magic = [header[0], header[1], header[2], header[3]];
    if magic != expected_magic {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!(
                "Invalid magic bytes: {magic:?}, expected {expected_magic:?}"
            )),
        )));
    }

    // Read command (12 bytes, null-terminated)
    let command_bytes = &header[4..16];
    let command_len = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = std::str::from_utf8(&command_bytes[..command_len]).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Invalid command: {e}"
        ))))
    })?;

    // Read payload length
    let length_bytes = [header[16], header[17], header[18], header[19]];
    let payload_length = u32::from_le_bytes(length_bytes) as usize;

    if payload_length > MAX_MESSAGE_PAYLOAD {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Payload length too large: {payload_length} bytes")),
        )));
    }

    // Read checksum
    let checksum = [header[20], header[21], header[22], header[23]];

    // Read payload
    let mut payload = vec![0u8; payload_length];
    if payload_length > 0 {
        reader.read_exact(&mut payload).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "IO error: {e}"
            ))))
        })?;
    }

    // Verify checksum
    let calculated_checksum = calculate_checksum(&payload);
    if calculated_checksum != checksum {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Checksum mismatch".to_string()),
        )));
    }

    // Deserialize message based on command
    let message = match command {
        "version" => NetworkMessage::Version(deserialize_version(&payload)?),
        "verack" => NetworkMessage::VerAck,
        "addr" => NetworkMessage::Addr(deserialize_addr(&payload)?),
        "addrv2" => NetworkMessage::AddrV2(deserialize_addrv2(&payload)?),
        "inv" => NetworkMessage::Inv(deserialize_inv(&payload)?),
        "getdata" => NetworkMessage::GetData(deserialize_getdata(&payload)?),
        "getheaders" => NetworkMessage::GetHeaders(deserialize_getheaders(&payload)?),
        "headers" => NetworkMessage::Headers(deserialize_headers(&payload)?),
        "block" => {
            let (block, witnesses) = deserialize_block_with_witnesses_pair(&payload)?;
            NetworkMessage::Block(Arc::new(block), witnesses)
        }
        "tx" => NetworkMessage::Tx(Arc::new(deserialize_tx(&payload)?)),
        "ping" => NetworkMessage::Ping(deserialize_ping(&payload)?),
        "pong" => NetworkMessage::Pong(deserialize_pong(&payload)?),
        "mempool" => NetworkMessage::MemPool,
        "feefilter" => NetworkMessage::FeeFilter(deserialize_feefilter(&payload)?),
        "getblocks" => NetworkMessage::GetBlocks(deserialize_getblocks(&payload)?),
        "getaddr" => NetworkMessage::GetAddr,
        "notfound" => NetworkMessage::NotFound(deserialize_notfound(&payload)?),
        "reject" => NetworkMessage::Reject(deserialize_reject(&payload)?),
        "sendheaders" => NetworkMessage::SendHeaders,
        "sendcmpct" => NetworkMessage::SendCmpct(deserialize_sendcmpct(&payload)?),
        "cmpctblock" => NetworkMessage::CmpctBlock(deserialize_cmpctblock(&payload)?),
        "getblocktxn" => NetworkMessage::GetBlockTxn(deserialize_getblocktxn(&payload)?),
        "blocktxn" => NetworkMessage::BlockTxn(deserialize_blocktxn(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "getutxoset" => NetworkMessage::GetUTXOSet(deserialize_getutxoset(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "utxoset" => NetworkMessage::UTXOSet(deserialize_utxoset(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "getfilteredblock" => {
            NetworkMessage::GetFilteredBlock(deserialize_getfilteredblock(&payload)?)
        }
        #[cfg(feature = "utxo-commitments")]
        "filteredblock" => NetworkMessage::FilteredBlock(deserialize_filteredblock(&payload)?),
        "getbanlist" => NetworkMessage::GetBanList(deserialize_getbanlist(&payload)?),
        "banlist" => NetworkMessage::BanList(deserialize_banlist(&payload)?),
        _ => {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned(format!("Unknown command: {command}")),
            )));
        }
    };

    Ok((message, MESSAGE_HEADER_SIZE + payload_length))
}

// Serialization helpers - Bitcoin P2P wire format encoding

/// Serialize NetworkAddress to Bitcoin wire format (26 bytes)
/// Format: services (8 bytes LE) + ip (16 bytes) + port (2 bytes BE)
fn serialize_network_address(addr: &crate::network::NetworkAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26);
    // services: u64 little-endian
    buf.extend_from_slice(&addr.services.to_le_bytes());
    // ip: [u8; 16] (IPv6 format, IPv4 is 0x0000...0000FFFF + IPv4 bytes)
    buf.extend_from_slice(&addr.ip);
    // port: u16 big-endian (network byte order)
    buf.extend_from_slice(&addr.port.to_be_bytes());
    buf
}

/// Deserialize NetworkAddress from Bitcoin wire format (26 bytes)
fn deserialize_network_address(data: &[u8]) -> Result<crate::network::NetworkAddress> {
    if data.len() < 26 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("NetworkAddress too short".to_string()),
        )));
    }

    // services: u64 little-endian (bytes 0-7)
    let services = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    // ip: [u8; 16] (bytes 8-23)
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&data[8..24]);

    // port: u16 big-endian (bytes 24-25)
    let port = u16::from_be_bytes([data[24], data[25]]);

    Ok(crate::network::NetworkAddress { services, ip, port })
}

/// Serialize VersionMessage to Bitcoin wire format
/// Format per Bitcoin protocol specification:
/// - version: i32 (4 bytes LE)
/// - services: u64 (8 bytes LE)
/// - timestamp: i64 (8 bytes LE)
/// - addr_recv: NetworkAddress (26 bytes)
/// - addr_from: NetworkAddress (26 bytes)
/// - nonce: u64 (8 bytes LE)
/// - user_agent: CompactSize + string bytes
/// - start_height: i32 (4 bytes LE)
/// - relay: u8 (1 byte, 0 or 1)
pub fn serialize_version(v: &crate::network::VersionMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();

    // version: i32 (4 bytes, little-endian)
    // Note: VersionMessage uses u32, but protocol expects i32
    buf.extend_from_slice(&(v.version as i32).to_le_bytes());

    // services: u64 (8 bytes, little-endian)
    buf.extend_from_slice(&v.services.to_le_bytes());

    // timestamp: i64 (8 bytes, little-endian)
    buf.extend_from_slice(&v.timestamp.to_le_bytes());

    // addr_recv: NetworkAddress (26 bytes)
    buf.extend_from_slice(&serialize_network_address(&v.addr_recv));

    // addr_from: NetworkAddress (26 bytes)
    buf.extend_from_slice(&serialize_network_address(&v.addr_from));

    // nonce: u64 (8 bytes, little-endian)
    buf.extend_from_slice(&v.nonce.to_le_bytes());

    // user_agent: CompactSize (varint) + string bytes
    let user_agent_bytes = v.user_agent.as_bytes();
    write_varint(&mut buf, user_agent_bytes.len() as u64)?;
    buf.extend_from_slice(user_agent_bytes);

    // start_height: i32 (4 bytes, little-endian)
    buf.extend_from_slice(&v.start_height.to_le_bytes());

    // relay: u8 (1 byte, 0 or 1)
    buf.push(if v.relay { 1 } else { 0 });

    Ok(buf)
}

/// Deserialize VersionMessage from Bitcoin wire format
pub fn deserialize_version(data: &[u8]) -> Result<crate::network::VersionMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    let mut cursor = Cursor::new(data);

    // version: i32 (4 bytes, little-endian)
    let mut version_bytes = [0u8; 4];
    cursor.read_exact(&mut version_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read version: {e}"
        ))))
    })?;
    let version = i32::from_le_bytes(version_bytes) as u32;

    // services: u64 (8 bytes, little-endian)
    let mut services_bytes = [0u8; 8];
    cursor.read_exact(&mut services_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read services: {e}"
        ))))
    })?;
    let services = u64::from_le_bytes(services_bytes);

    // timestamp: i64 (8 bytes, little-endian)
    let mut timestamp_bytes = [0u8; 8];
    cursor.read_exact(&mut timestamp_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read timestamp: {e}"
        ))))
    })?;
    let timestamp = i64::from_le_bytes(timestamp_bytes);

    // addr_recv: NetworkAddress (26 bytes)
    let mut addr_recv_bytes = [0u8; 26];
    cursor.read_exact(&mut addr_recv_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read addr_recv: {e}"
        ))))
    })?;
    let addr_recv = deserialize_network_address(&addr_recv_bytes)?;

    // addr_from: NetworkAddress (26 bytes)
    let mut addr_from_bytes = [0u8; 26];
    cursor.read_exact(&mut addr_from_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read addr_from: {e}"
        ))))
    })?;
    let addr_from = deserialize_network_address(&addr_from_bytes)?;

    // nonce: u64 (8 bytes, little-endian)
    let mut nonce_bytes = [0u8; 8];
    cursor.read_exact(&mut nonce_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read nonce: {e}"
        ))))
    })?;
    let nonce = u64::from_le_bytes(nonce_bytes);

    // user_agent: CompactSize (varint) + string bytes
    let user_agent_len = read_varint(&mut cursor)?;
    if user_agent_len > 10000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("User agent too long".to_string()),
        )));
    }
    let mut user_agent_bytes = vec![0u8; user_agent_len as usize];
    cursor.read_exact(&mut user_agent_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read user_agent: {e}"
        ))))
    })?;
    let user_agent = String::from_utf8(user_agent_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Invalid user_agent UTF-8: {e}"
        ))))
    })?;

    // start_height: i32 (4 bytes, little-endian)
    let mut start_height_bytes = [0u8; 4];
    cursor.read_exact(&mut start_height_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read start_height: {e}"
        ))))
    })?;
    let start_height = i32::from_le_bytes(start_height_bytes);

    // relay: u8 (1 byte, 0 or 1) - OPTIONAL field (version >= 70001)
    let relay = {
        let mut relay_byte = [0u8; 1];
        match cursor.read_exact(&mut relay_byte) {
            Ok(_) => relay_byte[0] != 0,
            Err(_) => true, // Default to relay=true if not present
        }
    };

    Ok(crate::network::VersionMessage {
        version,
        services,
        timestamp,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
        relay,
    })
}

/// Serialize AddrMessage to Bitcoin wire format (legacy addr)
/// Format: CompactSize(count) + [timestamp(4) + services(8) + addr(16) + port(2)]*
pub fn serialize_addr(a: &crate::network::AddrMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();
    write_varint(&mut buf, a.addresses.len() as u64)?;

    for addr in &a.addresses {
        // time: u32 (4 bytes, little-endian) - use 0 when not stored in NetworkAddress
        buf.extend_from_slice(&0u32.to_le_bytes());
        // services: u64 (8 bytes, little-endian)
        buf.extend_from_slice(&addr.services.to_le_bytes());
        // address: 16 bytes (IPv6, IPv4-mapped)
        buf.extend_from_slice(&addr.ip);
        // port: u16 (2 bytes, big-endian)
        buf.extend_from_slice(&addr.port.to_be_bytes());
    }
    Ok(buf)
}
pub fn deserialize_addr(data: &[u8]) -> Result<crate::network::AddrMessage> {
    use crate::varint::read_varint;
    use std::io::Read;

    let mut cursor = std::io::Cursor::new(data);
    let count = read_varint(&mut cursor)?;
    if count > 1000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Too many addresses in addr".to_string()),
        )));
    }

    let mut addresses = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut time_bytes = [0u8; 4];
        cursor.read_exact(&mut time_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Addr time: {e}"
            ))))
        })?;
        let _time = u32::from_le_bytes(time_bytes);

        let mut services_bytes = [0u8; 8];
        cursor.read_exact(&mut services_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Addr services: {e}"
            ))))
        })?;
        let services = u64::from_le_bytes(services_bytes);

        let mut ip = [0u8; 16];
        cursor.read_exact(&mut ip).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Addr ip: {e}"
            ))))
        })?;

        let mut port_bytes = [0u8; 2];
        cursor.read_exact(&mut port_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Addr port: {e}"
            ))))
        })?;
        let port = u16::from_be_bytes(port_bytes);

        addresses.push(crate::network::NetworkAddress { services, ip, port });
    }
    Ok(crate::network::AddrMessage { addresses })
}

/// Serialize AddrV2Message to Bitcoin wire format (BIP155)
/// Format: CompactSize(count) + [time(4) + services(8) + address_type(1) + address(var) + port(2)]*
pub fn serialize_addrv2(addrv2: &crate::network::AddrV2Message) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();

    // CompactSize: number of addresses
    write_varint(&mut buf, addrv2.addresses.len() as u64)?;

    // Serialize each address
    for addr in &addrv2.addresses {
        // time: u32 (4 bytes, little-endian)
        buf.extend_from_slice(&addr.time.to_le_bytes());

        // services: u64 (8 bytes, little-endian)
        buf.extend_from_slice(&addr.services.to_le_bytes());

        // address_type: u8 (1 byte)
        buf.push(addr.address_type as u8);

        // address: variable length based on type
        buf.extend_from_slice(&addr.address);

        // port: u16 (2 bytes, big-endian)
        buf.extend_from_slice(&addr.port.to_be_bytes());
    }

    Ok(buf)
}

/// Deserialize AddrV2Message from Bitcoin wire format (BIP155)
pub fn deserialize_addrv2(data: &[u8]) -> Result<crate::network::AddrV2Message> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    let mut cursor = Cursor::new(data);

    // CompactSize: number of addresses
    let count = read_varint(&mut cursor)?;
    if count > 1000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Too many addresses in addrv2".to_string()),
        )));
    }

    let mut addresses = Vec::with_capacity(count as usize);

    // Deserialize each address
    for _ in 0..count {
        // time: u32 (4 bytes, little-endian)
        let mut time_bytes = [0u8; 4];
        cursor.read_exact(&mut time_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read time: {e}"
            ))))
        })?;
        let time = u32::from_le_bytes(time_bytes);

        // services: u64 (8 bytes, little-endian)
        let mut services_bytes = [0u8; 8];
        cursor.read_exact(&mut services_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read services: {e}"
            ))))
        })?;
        let services = u64::from_le_bytes(services_bytes);

        // address_type: u8 (1 byte)
        let mut addr_type_byte = [0u8; 1];
        cursor.read_exact(&mut addr_type_byte).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read address_type: {e}"
            ))))
        })?;
        let address_type =
            crate::network::AddressType::from_u8(addr_type_byte[0]).ok_or_else(|| {
                ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                    "Invalid address type: {}",
                    addr_type_byte[0]
                ))))
            })?;

        // address: variable length based on type
        let addr_len = address_type.address_length();
        let mut address = vec![0u8; addr_len];
        cursor.read_exact(&mut address).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read address: {e}"
            ))))
        })?;

        // port: u16 (2 bytes, big-endian)
        let mut port_bytes = [0u8; 2];
        cursor.read_exact(&mut port_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read port: {e}"
            ))))
        })?;
        let port = u16::from_be_bytes(port_bytes);

        // Create NetworkAddressV2
        let addr_v2 =
            crate::network::NetworkAddressV2::new(time, services, address_type, address, port)?;

        addresses.push(addr_v2);
    }

    Ok(crate::network::AddrV2Message { addresses })
}

/// Serialize InvMessage to Bitcoin wire format
/// Format: count (varint) + count * (type u32 LE + hash 32 bytes)
pub fn serialize_inv(i: &crate::network::InvMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let capacity = 9 + (36 * i.inventory.len()); // varint + (4 + 32) per item
    let mut buf = Vec::with_capacity(capacity);

    write_varint(&mut buf, i.inventory.len() as u64)?;

    for item in &i.inventory {
        buf.extend_from_slice(&item.inv_type.to_le_bytes());
        buf.extend_from_slice(&item.hash);
    }

    Ok(buf)
}

/// Deserialize InvMessage from Bitcoin wire format
pub fn deserialize_inv(data: &[u8]) -> Result<crate::network::InvMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    if data.is_empty() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Inv message is empty".to_string()),
        )));
    }

    let mut cursor = Cursor::new(data);

    let count = read_varint(&mut cursor)? as usize;

    // Sanity check (max 50000 inventory items per message)
    if count > 50000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many inventory items: {count}")),
        )));
    }

    let mut inventory = Vec::with_capacity(count);

    for _ in 0..count {
        let mut type_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut type_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let inv_type = u32::from_le_bytes(type_bytes);

        let mut hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut hash).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;

        inventory.push(crate::network::InventoryVector { inv_type, hash });
    }

    Ok(crate::network::InvMessage { inventory })
}

/// Serialize GetDataMessage to Bitcoin wire format
/// Format: identical to Inv - count (varint) + count * (type u32 LE + hash 32 bytes)
pub fn serialize_getdata(g: &crate::network::GetDataMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let capacity = 9 + (36 * g.inventory.len());
    let mut buf = Vec::with_capacity(capacity);

    write_varint(&mut buf, g.inventory.len() as u64)?;

    for item in &g.inventory {
        buf.extend_from_slice(&item.inv_type.to_le_bytes());
        buf.extend_from_slice(&item.hash);
    }

    Ok(buf)
}

/// Deserialize GetDataMessage from Bitcoin wire format
pub fn deserialize_getdata(data: &[u8]) -> Result<crate::network::GetDataMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    if data.is_empty() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetData message is empty".to_string()),
        )));
    }

    let mut cursor = Cursor::new(data);

    let count = read_varint(&mut cursor)? as usize;

    if count > 50000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many inventory items: {count}")),
        )));
    }

    let mut inventory = Vec::with_capacity(count);

    for _ in 0..count {
        let mut type_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut type_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let inv_type = u32::from_le_bytes(type_bytes);

        let mut hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut hash).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;

        inventory.push(crate::network::InventoryVector { inv_type, hash });
    }

    Ok(crate::network::GetDataMessage { inventory })
}

/// Serialize GetHeadersMessage to Bitcoin wire format
/// Format: version (4 bytes LE) + hash_count (varint) + hashes (32 bytes each) + hash_stop (32 bytes)
pub fn serialize_getheaders(gh: &crate::network::GetHeadersMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;
    use std::io::Cursor;

    // Estimate capacity: 4 + 1-9 + (32 * hash_count) + 32
    let capacity = 4 + 9 + (32 * gh.block_locator_hashes.len()) + 32;
    let mut buf = Vec::with_capacity(capacity);

    // Protocol version (4 bytes, little-endian)
    buf.extend_from_slice(&(gh.version as i32).to_le_bytes());

    // Hash count (varint)
    let mut cursor = Cursor::new(&mut buf);
    cursor.set_position(4);
    write_varint(&mut buf, gh.block_locator_hashes.len() as u64)?;

    // Block locator hashes (32 bytes each, in internal byte order)
    for hash in &gh.block_locator_hashes {
        buf.extend_from_slice(hash);
    }

    // Hash stop (32 bytes)
    buf.extend_from_slice(&gh.hash_stop);

    Ok(buf)
}

/// Deserialize GetHeadersMessage from Bitcoin wire format
pub fn deserialize_getheaders(data: &[u8]) -> Result<crate::network::GetHeadersMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    if data.len() < 4 + 1 + 32 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetHeaders message too short".to_string()),
        )));
    }

    let mut cursor = Cursor::new(data);

    // Protocol version (4 bytes, little-endian)
    let mut version_bytes = [0u8; 4];
    std::io::Read::read_exact(&mut cursor, &mut version_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })?;
    let version = i32::from_le_bytes(version_bytes) as u32;

    // Hash count (varint)
    let hash_count = read_varint(&mut cursor)? as usize;

    // Sanity check on hash count
    if hash_count > 2000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many locator hashes: {hash_count}")),
        )));
    }

    // Block locator hashes
    let mut block_locator_hashes = Vec::with_capacity(hash_count);
    for _ in 0..hash_count {
        let mut hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut hash).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        block_locator_hashes.push(hash);
    }

    // Hash stop (32 bytes)
    let mut hash_stop = [0u8; 32];
    std::io::Read::read_exact(&mut cursor, &mut hash_stop).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })?;

    Ok(crate::network::GetHeadersMessage {
        version,
        block_locator_hashes,
        hash_stop,
    })
}

/// Serialize HeadersMessage to Bitcoin wire format
/// Format: count (varint) + headers (each: 80 bytes header + varint tx_count which is always 0)
pub fn serialize_headers(h: &crate::network::HeadersMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    // Estimate capacity: 1-9 varint + (81 bytes per header: 80 header + 1 tx_count)
    let capacity = 9 + (81 * h.headers.len());
    let mut buf = Vec::with_capacity(capacity);

    // Header count (varint)
    write_varint(&mut buf, h.headers.len() as u64)?;

    // Headers (80 bytes each + 1 byte tx_count = 0)
    for header in &h.headers {
        // version (4 bytes LE)
        buf.extend_from_slice(&(header.version as i32).to_le_bytes());
        // prev_block_hash (32 bytes)
        buf.extend_from_slice(&header.prev_block_hash);
        // merkle_root (32 bytes)
        buf.extend_from_slice(&header.merkle_root);
        // timestamp (4 bytes LE)
        buf.extend_from_slice(&(header.timestamp as u32).to_le_bytes());
        // bits (4 bytes LE)
        buf.extend_from_slice(&(header.bits as u32).to_le_bytes());
        // nonce (4 bytes LE)
        buf.extend_from_slice(&(header.nonce as u32).to_le_bytes());
        // tx_count (varint, always 0 for headers message)
        buf.push(0);
    }

    Ok(buf)
}

/// Deserialize HeadersMessage from Bitcoin wire format
pub fn deserialize_headers(data: &[u8]) -> Result<crate::network::HeadersMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    if data.is_empty() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Headers message is empty".to_string()),
        )));
    }

    let mut cursor = Cursor::new(data);

    // Header count (varint)
    let header_count = read_varint(&mut cursor)? as usize;

    // Sanity check on header count (max 2000 per Bitcoin protocol)
    if header_count > 2000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many headers: {header_count}")),
        )));
    }

    let mut headers = Vec::with_capacity(header_count);

    for _ in 0..header_count {
        // version (4 bytes LE)
        let mut version_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut version_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let version = i32::from_le_bytes(version_bytes) as i64;

        // prev_block_hash (32 bytes)
        let mut prev_block_hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut prev_block_hash).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;

        // merkle_root (32 bytes)
        let mut merkle_root = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut merkle_root).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;

        // timestamp (4 bytes LE)
        let mut timestamp_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut timestamp_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let timestamp = u32::from_le_bytes(timestamp_bytes) as u64;

        // bits (4 bytes LE)
        let mut bits_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut bits_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let bits = u32::from_le_bytes(bits_bytes) as u64;

        // nonce (4 bytes LE)
        let mut nonce_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut nonce_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let nonce = u32::from_le_bytes(nonce_bytes) as u64;

        // tx_count (varint, should be 0 for headers message, but we read and discard)
        let _tx_count = read_varint(&mut cursor)?;

        headers.push(crate::BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        });
    }

    Ok(crate::network::HeadersMessage { headers })
}

/// Serialize a block with its witness stacks for P2P relay.
///
/// `witnesses` is the per-tx, per-input witness stack (same layout as [`BlockMessage::witnesses`]).
/// Pass an empty slice to produce a legacy (pre-SegWit) serialization.
pub fn serialize_block_witnesses(
    b: &crate::Block,
    witnesses: &[Vec<blvm_consensus::segwit::Witness>],
) -> Result<Vec<u8>> {
    use crate::serialization::serialize_block_with_witnesses;

    let include_witness = !witnesses.is_empty() && witnesses.iter().any(|tx_w| !tx_w.is_empty());

    // Pad witnesses to match transaction count if a non-empty slice was provided but is shorter.
    let padded;
    let ws: &[Vec<blvm_consensus::segwit::Witness>] = if witnesses.len() < b.transactions.len() {
        padded = {
            let mut v = witnesses.to_vec();
            v.resize(b.transactions.len(), Vec::new());
            v
        };
        &padded
    } else {
        witnesses
    };

    Ok(serialize_block_with_witnesses(b, ws, include_witness))
}

/// Deserialize a block from P2P wire bytes, preserving its witness stacks.
///
/// Returns `(block, per_tx_witnesses)`.  The witness vec is empty if the message
/// was serialized in legacy (non-SegWit) format.
pub fn deserialize_block_with_witnesses_pair(
    data: &[u8],
) -> Result<(crate::Block, Vec<Vec<blvm_consensus::segwit::Witness>>)> {
    use crate::serialization::block::deserialize_block_with_witnesses;

    deserialize_block_with_witnesses(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}

/// Deserialize only the block, discarding any witness data.
///
/// Prefer [`deserialize_block_with_witnesses_pair`] for new call-sites; this
/// helper is retained for legacy uses where witnesses are not needed.
pub fn deserialize_block(data: &[u8]) -> Result<crate::Block> {
    let (block, _witnesses) = deserialize_block_with_witnesses_pair(data)?;
    Ok(block)
}

pub fn serialize_tx(tx: &crate::Transaction) -> Result<Vec<u8>> {
    Ok(crate::serialization::serialize_transaction(tx))
}
pub fn deserialize_tx(data: &[u8]) -> Result<crate::Transaction> {
    crate::serialization::deserialize_transaction(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}

/// Serialize PingMessage to Bitcoin wire format (8-byte nonce)
pub fn serialize_ping(p: &crate::network::PingMessage) -> Result<Vec<u8>> {
    Ok(p.nonce.to_le_bytes().to_vec())
}

/// Deserialize PingMessage from Bitcoin wire format
pub fn deserialize_ping(data: &[u8]) -> Result<crate::network::PingMessage> {
    if data.len() < 8 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Ping message too short: {} bytes", data.len())),
        )));
    }

    let nonce = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    Ok(crate::network::PingMessage { nonce })
}

/// Serialize PongMessage to Bitcoin wire format (8-byte nonce)
pub fn serialize_pong(p: &crate::network::PongMessage) -> Result<Vec<u8>> {
    Ok(p.nonce.to_le_bytes().to_vec())
}

/// Deserialize PongMessage from Bitcoin wire format
pub fn deserialize_pong(data: &[u8]) -> Result<crate::network::PongMessage> {
    if data.len() < 8 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Pong message too short: {} bytes", data.len())),
        )));
    }

    let nonce = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    Ok(crate::network::PongMessage { nonce })
}

/// Serialize FeeFilterMessage per BIP133: 8-byte feerate (LE)
pub fn serialize_feefilter(f: &crate::network::FeeFilterMessage) -> Result<Vec<u8>> {
    Ok(f.feerate.to_le_bytes().to_vec())
}
pub fn deserialize_feefilter(data: &[u8]) -> Result<crate::network::FeeFilterMessage> {
    if data.len() < 8 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("FeeFilter message too short".to_string()),
        )));
    }
    let feerate = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    Ok(crate::network::FeeFilterMessage { feerate })
}

/// Serialize GetBlocksMessage - same structure as GetHeaders (version + locator + hash_stop)
pub fn serialize_getblocks(gb: &crate::network::GetBlocksMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();
    buf.extend_from_slice(&gb.version.to_le_bytes());
    write_varint(&mut buf, gb.block_locator_hashes.len() as u64)?;
    for hash in &gb.block_locator_hashes {
        buf.extend_from_slice(hash);
    }
    buf.extend_from_slice(&gb.hash_stop);
    Ok(buf)
}
pub fn deserialize_getblocks(data: &[u8]) -> Result<crate::network::GetBlocksMessage> {
    use crate::varint::read_varint;
    use std::io::Read;

    if data.len() < 4 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetBlocks message too short".to_string()),
        )));
    }
    let mut cursor = std::io::Cursor::new(data);
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    cursor.set_position(4);

    let count = read_varint(&mut cursor)? as usize;
    if count > 101 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetBlocks locator too long".to_string()),
        )));
    }
    let mut block_locator_hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut hash = [0u8; 32];
        cursor.read_exact(&mut hash).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "GetBlocks: {e}"
            ))))
        })?;
        block_locator_hashes.push(hash);
    }
    let mut hash_stop = [0u8; 32];
    cursor.read_exact(&mut hash_stop).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "GetBlocks hash_stop: {e}"
        ))))
    })?;

    Ok(crate::network::GetBlocksMessage {
        version,
        block_locator_hashes,
        hash_stop,
    })
}

/// Serialize NotFoundMessage to Bitcoin wire format.
/// Format: identical to Inv/GetData - count (varint) + count * (type u32 LE + hash 32 bytes)
pub fn serialize_notfound(nf: &crate::network::NotFoundMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let capacity = 9 + (36 * nf.inventory.len());
    let mut buf = Vec::with_capacity(capacity);

    write_varint(&mut buf, nf.inventory.len() as u64)?;

    for item in &nf.inventory {
        buf.extend_from_slice(&item.inv_type.to_le_bytes());
        buf.extend_from_slice(&item.hash);
    }

    Ok(buf)
}

/// Deserialize NotFoundMessage from Bitcoin wire format.
pub fn deserialize_notfound(data: &[u8]) -> Result<crate::network::NotFoundMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    if data.is_empty() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("NotFound message is empty".to_string()),
        )));
    }

    let mut cursor = Cursor::new(data);

    let count = read_varint(&mut cursor)? as usize;

    if count > 50000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many inventory items: {count}")),
        )));
    }

    let mut inventory = Vec::with_capacity(count);

    for _ in 0..count {
        let mut type_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut type_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        let inv_type = u32::from_le_bytes(type_bytes);

        let mut hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut hash).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;

        inventory.push(crate::network::InventoryVector { inv_type, hash });
    }

    Ok(crate::network::NotFoundMessage { inventory })
}

/// Serialize RejectMessage per BIP61: message(12) + ccode(1) + reason(var) + data(32 optional)
pub fn serialize_reject(r: &crate::network::RejectMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::with_capacity(12 + 1 + 9 + r.reason.len() + 32);
    let msg_bytes = r.message.as_bytes();
    if msg_bytes.len() > 12 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Reject message field too long".to_string()),
        )));
    }
    buf.extend_from_slice(msg_bytes);
    buf.extend_from_slice(&[0u8; 12][msg_bytes.len()..]);

    buf.push(r.code);

    write_varint(&mut buf, r.reason.len() as u64)?;
    buf.extend_from_slice(r.reason.as_bytes());

    if let Some(ref h) = r.extra_data {
        buf.extend_from_slice(h);
    }
    Ok(buf)
}
pub fn deserialize_reject(data: &[u8]) -> Result<crate::network::RejectMessage> {
    use crate::varint::read_varint;

    if data.len() < 13 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Reject message too short".to_string()),
        )));
    }
    let message = String::from_utf8_lossy(&data[0..12])
        .trim_end_matches('\0')
        .to_string();
    let code = data[12];
    let mut cursor = std::io::Cursor::new(&data[13..]);
    let reason_len_u64 = read_varint(&mut cursor)?;
    let pos: usize = 13_usize.saturating_add(cursor.position() as usize);
    if reason_len_u64 > (data.len() as u64).saturating_sub(pos as u64) {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Reject reason truncated".to_string()),
        )));
    }
    let reason_len: usize = reason_len_u64.try_into().map_err(|_| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
            "Reject reason length out of range".to_string(),
        )))
    })?;
    let end = pos.checked_add(reason_len).ok_or_else(|| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
            "Reject reason length out of range".to_string(),
        )))
    })?;
    if end > data.len() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Reject reason truncated".to_string()),
        )));
    }
    let reason = String::from_utf8_lossy(&data[pos..end]).to_string();
    let pos = end;
    let extra_data = if data.len() >= pos + 32 {
        Some({
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[pos..pos + 32]);
            h
        })
    } else {
        None
    };
    Ok(crate::network::RejectMessage {
        message,
        code,
        reason,
        extra_data,
    })
}

/// BIP152: sendcmpct - 1 byte prefer_cmpct + 8 bytes version (LE)
pub fn serialize_sendcmpct(sc: &crate::network::SendCmpctMessage) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(9);
    buf.push(sc.prefer_cmpct);
    buf.extend_from_slice(&sc.version.to_le_bytes());
    Ok(buf)
}
pub fn deserialize_sendcmpct(data: &[u8]) -> Result<crate::network::SendCmpctMessage> {
    if data.len() < 9 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("SendCmpct message too short".to_string()),
        )));
    }
    Ok(crate::network::SendCmpctMessage {
        prefer_cmpct: data[0],
        version: u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]),
    })
}

/// BIP152: cmpctblock - header(80) + nonce(8) + shortids(varint+6*count) + prefilled(varint+each: diff_index+tx)
pub fn serialize_cmpctblock(cb: &crate::network::CmpctBlockMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();
    buf.extend_from_slice(&crate::serialization::serialize_block_header(&cb.header));
    buf.extend_from_slice(&cb.nonce.to_le_bytes());
    write_varint(&mut buf, cb.short_ids.len() as u64)?;
    for sid in &cb.short_ids {
        buf.extend_from_slice(sid);
    }
    write_varint(&mut buf, cb.prefilled_txs.len() as u64)?;
    let mut last_index = -1i64;
    for pt in &cb.prefilled_txs {
        let diff = (pt.index as i64) - last_index - 1;
        write_varint(&mut buf, diff as u64)?;
        last_index = pt.index as i64;
        let tx_bytes = match &pt.witness {
            Some(wit) if wit.iter().any(|w| !w.is_empty()) => {
                crate::serialization::serialize_transaction_with_witness(&pt.tx, wit)
            }
            _ => crate::serialization::serialize_transaction(&pt.tx),
        };
        buf.extend_from_slice(&tx_bytes);
    }
    Ok(buf)
}
pub fn deserialize_cmpctblock(data: &[u8]) -> Result<crate::network::CmpctBlockMessage> {
    use crate::varint::read_varint;
    use std::io::Read;

    /// BIP152 wire sanity bound (aligns with `getblocktxn` and inventory caps in this module).
    const MAX_CMPCT_SHORTIDS: u64 = 50_000;
    const MAX_CMPCT_PREFILLED: u64 = 50_000;

    if data.len() < 80 + 8 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("CmpctBlock message too short".to_string()),
        )));
    }
    let header = crate::serialization::deserialize_block_header(&data[0..80]).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })?;
    let nonce = u64::from_le_bytes([
        data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
    ]);
    let mut cursor = std::io::Cursor::new(&data[88..]);
    let shortids_len_u64 = read_varint(&mut cursor)?;
    if shortids_len_u64 > MAX_CMPCT_SHORTIDS {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("CmpctBlock too many shortids".to_string()),
        )));
    }
    let shortids_len: usize = shortids_len_u64.try_into().map_err(|_| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
            "CmpctBlock shortid count out of range".to_string(),
        )))
    })?;
    let rem_after_count = data.len().saturating_sub(88 + cursor.position() as usize);
    let need_shortids = shortids_len.checked_mul(6).ok_or_else(|| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
            "CmpctBlock shortid size overflow".to_string(),
        )))
    })?;
    if need_shortids > rem_after_count {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("CmpctBlock shortids truncated".to_string()),
        )));
    }
    let mut short_ids = Vec::with_capacity(shortids_len);
    for _ in 0..shortids_len {
        let mut sid = [0u8; 6];
        cursor.read_exact(&mut sid).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "CmpctBlock shortid: {e}"
            ))))
        })?;
        short_ids.push(sid);
    }
    let prefilled_len_u64 = read_varint(&mut cursor)?;
    if prefilled_len_u64 > MAX_CMPCT_PREFILLED {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("CmpctBlock too many prefilled txs".to_string()),
        )));
    }
    let prefilled_len: usize = prefilled_len_u64.try_into().map_err(|_| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
            "CmpctBlock prefilled count out of range".to_string(),
        )))
    })?;
    let mut prefilled_txs = Vec::with_capacity(prefilled_len);
    let mut last_index: i64 = -1;
    let mut pos;
    for _ in 0..prefilled_len {
        let diff = read_varint(&mut cursor)? as i64;
        if diff < 0 {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("CmpctBlock prefilled index diff invalid".to_string()),
            )));
        }
        let index = last_index
            .checked_add(diff)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| {
                ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
                    "CmpctBlock prefilled index overflow".to_string(),
                )))
            })?;
        if index > 0xffff {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("CmpctBlock prefilled index too large".to_string()),
            )));
        }
        last_index = index;
        pos = cursor.position() as usize;
        let slice = &data[88..];
        if pos >= slice.len() {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("CmpctBlock prefilled tx truncated".to_string()),
            )));
        }
        // Use deserialize_transaction_with_witness: returns actual bytes consumed.
        // Core sends prefilled txs with TX_WITH_WITNESS (SegWit); serialize_transaction().len()
        // would undercount and corrupt subsequent parsing.
        let (tx, witnesses, consumed) = crate::serialization::deserialize_transaction_with_witness(
            &slice[pos..],
        )
        .map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        cursor.set_position((pos + consumed) as u64);
        let witness = witnesses.iter().any(|w| !w.is_empty()).then_some(witnesses);
        prefilled_txs.push(crate::network::PrefilledTransaction {
            index: index as u16,
            tx,
            witness,
        });
    }
    Ok(crate::network::CmpctBlockMessage {
        header,
        nonce,
        short_ids,
        prefilled_txs,
    })
}

/// BIP152: getblocktxn - block_hash(32) + indexes(varint count + diff-encoded varints)
pub fn serialize_getblocktxn(gbt: &crate::network::GetBlockTxnMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();
    buf.extend_from_slice(&gbt.block_hash);
    write_varint(&mut buf, gbt.indices.len() as u64)?;
    let mut last: i64 = -1;
    for &idx in &gbt.indices {
        let diff = (idx as i64) - last - 1;
        if diff < 0 {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("GetBlockTxn indices must be strictly increasing".to_string()),
            )));
        }
        write_varint(&mut buf, diff as u64)?;
        last = idx as i64;
    }
    Ok(buf)
}
pub fn deserialize_getblocktxn(data: &[u8]) -> Result<crate::network::GetBlockTxnMessage> {
    use crate::varint::read_varint;

    if data.len() < 32 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetBlockTxn message too short".to_string()),
        )));
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[0..32]);
    let mut cursor = std::io::Cursor::new(&data[32..]);
    let count = read_varint(&mut cursor)? as usize;
    if count > 50000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetBlockTxn too many indices".to_string()),
        )));
    }
    let mut indices = Vec::with_capacity(count);
    let mut last: i64 = -1;
    for _ in 0..count {
        let diff = read_varint(&mut cursor)? as i64;
        if diff < 0 {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("GetBlockTxn index diff invalid".to_string()),
            )));
        }
        last = last
            .checked_add(diff)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| {
                ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(
                    "GetBlockTxn index overflow".to_string(),
                )))
            })?;
        if last > 0xffff {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("GetBlockTxn index too large".to_string()),
            )));
        }
        indices.push(last as u16);
    }
    Ok(crate::network::GetBlockTxnMessage {
        block_hash,
        indices,
    })
}

/// BIP152: blocktxn - block_hash(32) + count(varint) + transactions
pub fn serialize_blocktxn(bt: &crate::network::BlockTxnMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();
    buf.extend_from_slice(&bt.block_hash);
    write_varint(&mut buf, bt.transactions.len() as u64)?;
    match (&bt.witnesses, bt.transactions.len()) {
        (Some(witnesses), len) if witnesses.len() == len => {
            for (tx, wit) in bt.transactions.iter().zip(witnesses.iter()) {
                buf.extend_from_slice(&crate::serialization::serialize_transaction_with_witness(
                    tx, wit,
                ));
            }
        }
        _ => {
            for tx in &bt.transactions {
                buf.extend_from_slice(&crate::serialization::serialize_transaction(tx));
            }
        }
    }
    Ok(buf)
}
pub fn deserialize_blocktxn(data: &[u8]) -> Result<crate::network::BlockTxnMessage> {
    use crate::varint::read_varint;

    if data.len() < 32 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("BlockTxn message too short".to_string()),
        )));
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[0..32]);
    let mut cursor = std::io::Cursor::new(&data[32..]);
    let count = read_varint(&mut cursor)? as usize;
    if count > 2000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("BlockTxn too many transactions".to_string()),
        )));
    }
    let mut transactions = Vec::with_capacity(count);
    let mut all_witnesses = Vec::with_capacity(count);
    let mut pos = 32 + (cursor.position() as usize);
    for _ in 0..count {
        if pos >= data.len() {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned("BlockTxn truncated".to_string()),
            )));
        }
        // BIP152: blocktxn txs use same format as block (TX_WITH_WITNESS). Use
        // deserialize_transaction_with_witness for correct bytes consumed.
        let (tx, witnesses, consumed) = crate::serialization::deserialize_transaction_with_witness(
            &data[pos..],
        )
        .map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
        })?;
        pos += consumed;
        transactions.push(tx);
        all_witnesses.push(witnesses);
    }
    let witnesses = all_witnesses
        .iter()
        .any(|w| w.iter().any(|s| !s.is_empty()))
        .then_some(all_witnesses);
    Ok(crate::network::BlockTxnMessage {
        block_hash,
        transactions,
        witnesses,
    })
}

#[cfg(feature = "utxo-commitments")]
fn serialize_getutxoset(gus: &crate::commons::GetUTXOSetMessage) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&gus.height.to_le_bytes());
    buf.extend_from_slice(&gus.block_hash);
    Ok(buf)
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_getutxoset(data: &[u8]) -> Result<crate::commons::GetUTXOSetMessage> {
    if data.len() < 40 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetUTXOSet message too short".to_string()),
        )));
    }
    let height = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[8..40]);
    Ok(crate::commons::GetUTXOSetMessage { height, block_hash })
}

#[cfg(feature = "utxo-commitments")]
fn serialize_utxoset(us: &crate::commons::UTXOSetMessage) -> Result<Vec<u8>> {
    bincode::serialize(us).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_utxoset(data: &[u8]) -> Result<crate::commons::UTXOSetMessage> {
    bincode::deserialize(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}

#[cfg(feature = "utxo-commitments")]
fn serialize_getfilteredblock(gfb: &crate::commons::GetFilteredBlockMessage) -> Result<Vec<u8>> {
    bincode::serialize(gfb).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_getfilteredblock(data: &[u8]) -> Result<crate::commons::GetFilteredBlockMessage> {
    bincode::deserialize(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}

#[cfg(feature = "utxo-commitments")]
fn serialize_filteredblock(fb: &crate::commons::FilteredBlockMessage) -> Result<Vec<u8>> {
    bincode::serialize(fb).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_filteredblock(data: &[u8]) -> Result<crate::commons::FilteredBlockMessage> {
    bincode::deserialize(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}

fn serialize_getbanlist(gbl: &crate::commons::GetBanListMessage) -> Result<Vec<u8>> {
    bincode::serialize(gbl).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}
fn deserialize_getbanlist(data: &[u8]) -> Result<crate::commons::GetBanListMessage> {
    bincode::deserialize(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}

fn serialize_banlist(bl: &crate::commons::BanListMessage) -> Result<Vec<u8>> {
    bincode::serialize(bl).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}
fn deserialize_banlist(data: &[u8]) -> Result<crate::commons::BanListMessage> {
    bincode::deserialize(data).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string())))
    })
}
