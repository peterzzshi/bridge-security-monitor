use anyhow::{bail, Context, Result};
use apache_avro::Decimal;
use dex_ingester_common::{BridgeTransferEvent, Event, TransferDirection};
use ethers::abi::{decode as abi_decode, ParamType, Token};
use ethers::contract::{EthEvent, EthLogDecode};
use ethers::prelude::*;
use num_bigint::BigInt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeProtocol {
    Wormhole,
    LayerZero,
}

impl BridgeProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wormhole => "wormhole",
            Self::LayerZero => "layerzero",
        }
    }
}

impl FromStr for BridgeProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "wormhole" => Ok(Self::Wormhole),
            "layerzero" => Ok(Self::LayerZero),
            other => bail!("Unknown bridge protocol: {}", other),
        }
    }
}

fn u256_to_decimal(value: U256) -> Decimal {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    let big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);
    Decimal::from(big_int.to_signed_bytes_be())
}

/// Normalize amount to 18 decimals: rawAmount * 10^(18 - decimals)
fn normalize_to_18_decimals(amount: Decimal, decimals: u8) -> Decimal {
    if decimals == 18 {
        return amount;
    }
    let scale_factor = 18i32 - decimals as i32;
    if scale_factor == 0 {
        return amount;
    }
    let ten = BigInt::from(10);
    let multiplier = if scale_factor > 0 {
        ten.pow(scale_factor as u32)
    } else {
        // Scale down if decimals > 18 (shouldn't happen for standard tokens)
        return amount;
    };

    // Convert Decimal to BigInt, multiply, convert back
    let amount_bytes: Vec<u8> = amount.try_into().unwrap_or_else(|_| vec![0]);
    let amount_bigint = BigInt::from_signed_bytes_be(&amount_bytes);
    let normalized = amount_bigint * multiplier;
    Decimal::from(normalized.to_signed_bytes_be())
}

// LogMessagePublished is emitted by the Wormhole core contract (0x98f3c9e6...) when any
// cross-chain message is published, including token transfers initiated at the token bridge.
// Real ABI: LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel)
#[derive(Debug, Clone, PartialEq, EthEvent)]
#[ethevent(name = "LogMessagePublished")]
pub struct WormholeLogMessagePublished {
    #[ethevent(indexed)]
    pub sender: Address,
    pub sequence: u64,
    pub nonce: u32,
    pub payload: Bytes,
    pub consistency_level: u8,
}

// Real ITokenBridge ABI: TransferRedeemed(uint16 indexed emitterChainId, bytes32 indexed emitterAddress, uint64 indexed sequence)
// Verified against on-chain topic0 0xcaf280c8...ba317c169 from Alchemy eth_getLogs.
// All three fields are indexed; the event carries no amount, recipient, or token — those are
// encoded in the VAA payload submitted with the redeem call (requires calldata parsing).
#[derive(Debug, Clone, PartialEq, EthEvent)]
#[ethevent(name = "TransferRedeemed")]
pub struct WormholeTransferRedeemed {
    #[ethevent(indexed)]
    pub emitter_chain_id: u16,
    #[ethevent(indexed)]
    pub emitter_address: [u8; 32],
    #[ethevent(indexed)]
    pub sequence: u64,
}

// Real V2 ABI: PacketSent(bytes encodedPayload, bytes options, address sendLibrary)
// All fields are non-indexed (no topics beyond topic0).
// encodedPayload is tightly packed: version(1) | nonce(8) | srcEid(4) | sender(32) | dstEid(4) | receiver(32) | guid(32) | message(...)
// dstEid at [45,49), nonce at [1,9), guid at [81,113). Decoded in the match arm below.
//
// Destination side: PacketVerified(Origin origin, address receiver, bytes32 payloadHash)
// where Origin = { uint32 srcEid, bytes32 sender, uint64 nonce }. No indexed fields.
#[derive(Debug, Clone, PartialEq, EthEvent)]
#[ethevent(name = "PacketSent")]
pub struct LayerZeroPacketSent {
    pub encoded_payload: Bytes,
    pub options: Bytes,
    pub send_library: Address,
}

// PacketVerified((uint32,bytes32,uint64),address,bytes32)
// ethers-rs EthEvent derive cannot handle tuple (struct) params, so we decode manually.
// topic0 = keccak256("PacketVerified((uint32,bytes32,uint64),address,bytes32)")
fn packet_verified_topic0() -> H256 {
    H256::from(ethers::utils::keccak256(
        b"PacketVerified((uint32,bytes32,uint64),address,bytes32)",
    ))
}

struct PacketVerifiedDecoded {
    src_eid: u32,
    nonce: u64,
    receiver: Address,
}

fn decode_packet_verified(log: &Log) -> Result<PacketVerifiedDecoded> {
    // All fields are non-indexed; entire event is in log.data.
    // ABI layout: tuple(uint32,bytes32,uint64) origin | address receiver | bytes32 payloadHash
    let types = vec![
        ParamType::Tuple(vec![
            ParamType::Uint(32),
            ParamType::FixedBytes(32),
            ParamType::Uint(64),
        ]),
        ParamType::Address,
        ParamType::FixedBytes(32),
    ];
    let tokens = abi_decode(&types, &log.data).context("abi decode PacketVerified")?;
    let origin = match tokens.get(0) {
        Some(Token::Tuple(t)) => t.clone(),
        _ => bail!("missing origin tuple"),
    };
    let src_eid = match origin.get(0) {
        Some(Token::Uint(v)) => v.low_u32(),
        _ => bail!("missing srcEid"),
    };
    let nonce = match origin.get(2) {
        Some(Token::Uint(v)) => v.low_u64(),
        _ => bail!("missing nonce"),
    };
    let receiver = match tokens.get(1) {
        Some(Token::Address(a)) => *a,
        _ => bail!("missing receiver"),
    };
    Ok(PacketVerifiedDecoded {
        src_eid,
        nonce,
        receiver,
    })
}

/// Wormhole reports an EVM emitter as its 20-byte address left-padded to 32 bytes. The unlock
/// path reads that padded form out of the VAA, so the lock path must produce the same bytes or
/// the two legs never share a `message_hash`.
fn wormhole_emitter(address: Address, chain: u16) -> (u16, String) {
    let mut emitter = [0u8; 32];
    emitter[12..].copy_from_slice(address.as_bytes());
    (chain, hex::encode(emitter))
}

pub fn decode(
    log: &Log,
    protocol: BridgeProtocol,
    chain: String,
    chain_name: String,
    bridge_address: String,
    event_id: String,
    block_number: i64,
    block_timestamp: i64,
    transaction_hash: H256,
    log_index: i32,
    event_timestamp: i64,
    gas_used: i64,
    gas_price: String,
    token: String,
    token_symbol: Option<String>,
    token_decimals: Option<u8>,
    transaction_input: Option<&ethers::types::Bytes>,
) -> Result<Event> {
    tracing::info!(
        protocol = protocol.as_str(),
        block = block_number,
        tx = %transaction_hash,
        topics = ?log.topics,
        data = ?log.data,
        "raw EVM log"
    );
    match protocol {
        BridgeProtocol::Wormhole => {
            if log.topics[0] == WormholeLogMessagePublished::signature() {
                let event =
                    <WormholeLogMessagePublished as EthLogDecode>::decode_log(&log.clone().into())
                        .context("failed to decode LogMessagePublished")?;

                // The core contract publishes for every Wormhole application. Only messages from
                // this bridge's token contract are token transfers; `sender` is indexed, so the
                // emitting contract is topics[1] and can be checked before decoding the payload.
                let token_bridge = H160::from_str(&bridge_address)
                    .with_context(|| format!("invalid bridge address: {bridge_address}"))?;
                if event.sender != token_bridge {
                    bail!(
                        "LogMessagePublished from a different sender: {:?}",
                        event.sender
                    );
                }

                // TokenBridge Transfer payload layout (all fields big-endian), matching
                // solana-ingester/src/vaa_parser.rs:
                // payloadID u8 [0] | amount u256 [1..33] | tokenAddress [u8;32] [33..65] |
                // tokenChain u16 [65..67] | to [u8;32] [67..99] | toChain u16 [99..101] |
                // fee u256 [101..133]
                let payload = event.payload.as_ref();
                if payload.len() < 133 {
                    bail!(
                        "Payload too short for token transfer: {} bytes",
                        payload.len()
                    );
                }
                if payload[0] != 1 {
                    bail!("Not a token transfer payload (type {})", payload[0]);
                }

                // Extract amount (bytes 1-33, big-endian U256)
                let amount_bytes: [u8; 32] = payload[1..33].try_into()?;
                let raw_amount = u256_to_decimal(U256::from_big_endian(&amount_bytes));

                // Extract destination Wormhole chain (bytes 99-101) and recipient (bytes 67-99)
                let target_chain = u16::from_be_bytes([payload[99], payload[100]]);

                let recipient = &payload[67..99];

                let normalized_amount = token_decimals
                    .map(|d| normalize_to_18_decimals(raw_amount.clone(), d))
                    .unwrap_or(raw_amount);

                // VAA emitter identity: the token bridge contract, left-padded to 32 bytes as
                // Wormhole reports it, so the triple matches what the unlock side reads.
                let emitter = wormhole_emitter(token_bridge, 2); // Ethereum mainnet is chain 2
                let message_hash = format!("{}:{}:{}", emitter.0, emitter.1, event.sequence);

                Ok(Event::Transfer(BridgeTransferEvent {
                    event_id,
                    block_number,
                    block_timestamp,
                    transaction_hash: format!("{:?}", transaction_hash),
                    log_index,
                    chain,
                    chain_name,
                    bridge_address,
                    protocol: protocol.as_str().to_string(),
                    direction: TransferDirection::Lock,
                    gas_used,
                    gas_price: gas_price.clone(),
                    event_timestamp,
                    sender: format!("{:?}", event.sender),
                    recipient: format!("0x{}", hex::encode(recipient)),
                    token: token.clone(),
                    token_symbol: token_symbol.clone(),
                    amount: normalized_amount,
                    destination_chain: Some(format!("wormhole:{}", target_chain)),
                    source_chain: None,
                    message_hash: Some(message_hash),
                    sequence_number: Some(event.sequence as i64),
                }))
            } else if log.topics[0] == WormholeTransferRedeemed::signature() {
                let event =
                    <WormholeTransferRedeemed as EthLogDecode>::decode_log(&log.clone().into())
                        .context("failed to decode WormholeTransferRedeemed")?;

                // Parse VAA from transaction input calldata to extract the real transfer amount
                let amount = if let Some(input) = transaction_input {
                    match crate::vaa_parser::extract_vaa_from_calldata(input) {
                        Ok(vaa_bytes) => {
                            match crate::vaa_parser::parse_token_bridge_transfer(&vaa_bytes) {
                                Ok(transfer) => {
                                    let normalized_amount = token_decimals
                                        .map(|d| {
                                            normalize_to_18_decimals(transfer.amount.clone(), d)
                                        })
                                        .unwrap_or(transfer.amount);
                                    normalized_amount
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        tx = %transaction_hash,
                                        "Failed to parse VAA payload: {:#}",
                                        e
                                    );
                                    Decimal::from(vec![0])
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                tx = %transaction_hash,
                                "Failed to extract VAA from calldata: {:#}",
                                e
                            );
                            Decimal::from(vec![0])
                        }
                    }
                } else {
                    tracing::warn!(
                        tx = %transaction_hash,
                        "No transaction input available for VAA parsing"
                    );
                    Decimal::from(vec![0])
                };

                Ok(Event::Transfer(BridgeTransferEvent {
                    event_id,
                    block_number,
                    block_timestamp,
                    transaction_hash: format!("{:?}", transaction_hash),
                    log_index,
                    chain,
                    chain_name,
                    bridge_address,
                    protocol: protocol.as_str().to_string(),
                    direction: TransferDirection::Unlock,
                    gas_used,
                    gas_price: gas_price.clone(),
                    event_timestamp,
                    sender: format!("0x{}", hex::encode(event.emitter_address)),
                    recipient: "".to_string(),
                    token: token.clone(),
                    token_symbol: token_symbol.clone(),
                    amount,
                    destination_chain: None,
                    source_chain: Some(format!("eip155:{}", event.emitter_chain_id)),
                    // VAA identity: emitter_chain:emitter_address:sequence uniquely identifies a
                    // Wormhole message and enables cross-chain correlation when the Solana side
                    // also parses VAA data.
                    message_hash: Some(format!(
                        "{}:{}:{}",
                        event.emitter_chain_id,
                        hex::encode(event.emitter_address),
                        event.sequence,
                    )),
                    sequence_number: Some(event.sequence as i64),
                }))
            } else {
                bail!("unknown Wormhole event signature: {:?}", log.topics[0])
            }
        }
        BridgeProtocol::LayerZero => {
            if log.topics[0] == LayerZeroPacketSent::signature() {
                let event = <LayerZeroPacketSent as EthLogDecode>::decode_log(&log.clone().into())
                    .context("failed to decode LayerZeroPacketSent")?;
                // encodedPayload layout (tightly packed, big-endian):
                // [0]     version  uint8
                // [1..9]  nonce    uint64
                // [9..13] srcEid   uint32
                // [13..45] sender  bytes32
                // [45..49] dstEid  uint32
                // [49..81] receiver bytes32
                // [81..113] guid   bytes32
                let payload = event.encoded_payload.as_ref();
                let (src_eid, dst_eid, nonce) = if payload.len() >= 113 {
                    let src_eid = u32::from_be_bytes(payload[9..13].try_into().unwrap_or([0; 4]));
                    let dst_eid = u32::from_be_bytes(payload[45..49].try_into().unwrap_or([0; 4]));
                    let nonce = u64::from_be_bytes(payload[1..9].try_into().unwrap_or([0; 8]));
                    (src_eid, dst_eid, nonce)
                } else {
                    (0u32, 0u32, 0u64)
                };

                // Construct canonical message_hash from srcEid and nonce (shared between PacketSent and PacketVerified)
                let message_hash = if src_eid > 0 && nonce > 0 {
                    Some(format!("{}:{}", src_eid, nonce))
                } else {
                    None
                };

                Ok(Event::Transfer(BridgeTransferEvent {
                    event_id,
                    block_number,
                    block_timestamp,
                    transaction_hash: format!("{:?}", transaction_hash),
                    log_index,
                    chain,
                    chain_name,
                    bridge_address,
                    protocol: protocol.as_str().to_string(),
                    direction: TransferDirection::Lock,
                    gas_used,
                    gas_price: gas_price.clone(),
                    event_timestamp,
                    sender: "".to_string(),
                    recipient: "".to_string(),
                    token: "".to_string(),
                    token_symbol: None,
                    amount: Decimal::from(vec![0]),
                    destination_chain: Some(format!("eip155:{}", dst_eid)),
                    source_chain: None,
                    message_hash,
                    sequence_number: Some(nonce as i64),
                }))
            } else if log.topics[0] == packet_verified_topic0() {
                let event = decode_packet_verified(log)
                    .context("failed to decode LayerZeroPacketVerified")?;

                // Use same canonical hash: srcEid:nonce
                let message_hash = if event.src_eid > 0 && event.nonce > 0 {
                    Some(format!("{}:{}", event.src_eid, event.nonce))
                } else {
                    None
                };

                Ok(Event::Transfer(BridgeTransferEvent {
                    event_id,
                    block_number,
                    block_timestamp,
                    transaction_hash: format!("{:?}", transaction_hash),
                    log_index,
                    chain,
                    chain_name,
                    bridge_address,
                    protocol: protocol.as_str().to_string(),
                    direction: TransferDirection::Unlock,
                    gas_used,
                    gas_price: gas_price.clone(),
                    event_timestamp,
                    sender: "".to_string(),
                    recipient: format!("{:?}", event.receiver),
                    token: "".to_string(),
                    token_symbol: None,
                    amount: Decimal::from(vec![0]),
                    destination_chain: None,
                    source_chain: Some(format!("eip155:{}", event.src_eid)),
                    message_hash,
                    sequence_number: Some(event.nonce as i64),
                }))
            } else {
                bail!("unknown LayerZero event signature: {:?}", log.topics[0])
            }
        }
    }
}
