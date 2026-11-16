use anyhow::{bail, Context, Result};
use apache_avro::Decimal;
use dex_ingester_common::{
    wormhole_payload_amount, BridgeTransferEvent, DecodeOutcome, Event, TransferDirection,
};
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
    transaction_input: Option<&ethers::types::Bytes>,
) -> Result<DecodeOutcome> {
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
                    // The core contract publishes for every Wormhole application. A message from
                    // a different application is routine, not a decode failure.
                    return Ok(DecodeOutcome::NotReported);
                }

                // TokenBridge Transfer payload layout (all fields big-endian), matching
                // solana-ingester/src/vaa_parser.rs:
                // payloadID u8 [0] | amount u256 [1..33] | tokenAddress [u8;32] [33..65] |
                // tokenChain u16 [65..67] | to [u8;32] [67..99] | toChain u16 [99..101] |
                // fee u256 [101..133]
                let payload = event.payload.as_ref();
                if payload.len() < 133 {
                    // A message from this bridge that is too short to be a token transfer:
                    // attesting or governance traffic travels the same path.
                    return Ok(DecodeOutcome::NotReported);
                }
                if payload[0] != 1 {
                    return Ok(DecodeOutcome::NotReported);
                }

                // Extract amount (bytes 1-33, big-endian U256)
                let amount_bytes: [u8; 32] = payload[1..33].try_into()?;
                let raw_amount = u256_to_decimal(U256::from_big_endian(&amount_bytes));

                // Extract destination Wormhole chain (bytes 99-101) and recipient (bytes 67-99)
                let target_chain = u16::from_be_bytes([payload[99], payload[100]]);

                let recipient = &payload[67..99];

                // The payload amount is 8-decimal regardless of the token, so it converts by a
                // fixed factor. See `dex_ingester_common::wormhole_payload_amount`.
                let normalized_amount = wormhole_payload_amount(raw_amount);

                // VAA emitter identity: the token bridge contract, left-padded to 32 bytes as
                // Wormhole reports it, so the triple matches what the unlock side reads.
                let emitter = wormhole_emitter(token_bridge, 2); // Ethereum mainnet is chain 2
                let message_hash = format!("{}:{}:{}", emitter.0, emitter.1, event.sequence);

                Ok(DecodeOutcome::Decoded(Event::Transfer(
                    BridgeTransferEvent {
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
                    },
                )))
            } else if log.topics[0] == WormholeTransferRedeemed::signature() {
                let event =
                    <WormholeTransferRedeemed as EthLogDecode>::decode_log(&log.clone().into())
                        .context("failed to decode WormholeTransferRedeemed")?;

                // The redeem event carries no amount; it is only in the VAA submitted with the
                // call. Without it there is no amount to report, and a placeholder zero would
                // read downstream as a lock/unlock pair whose amounts differ by the whole
                // transfer — so the event is dropped rather than fabricated. Every branch below
                // is lost data, not an unrelated log.
                let Some(input) = transaction_input else {
                    return Ok(DecodeOutcome::DataLost(
                        "no transaction input available for VAA parsing".to_string(),
                    ));
                };
                let vaa_bytes = match crate::vaa_parser::extract_vaa_from_calldata(input) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Ok(DecodeOutcome::DataLost(format!(
                            "failed to extract VAA from calldata: {e:#}"
                        )))
                    }
                };
                let transfer = match crate::vaa_parser::parse_token_bridge_transfer(&vaa_bytes) {
                    Ok(transfer) => transfer,
                    Err(e) => {
                        return Ok(DecodeOutcome::DataLost(format!(
                            "failed to parse VAA payload: {e:#}"
                        )))
                    }
                };
                let amount = wormhole_payload_amount(transfer.amount);

                Ok(DecodeOutcome::Decoded(Event::Transfer(
                    BridgeTransferEvent {
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
                    },
                )))
            } else {
                // The subscription filters by address, so this contract emits this signature
                // for a purpose this decoder does not model. Not a failure.
                Ok(DecodeOutcome::NotReported)
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

                Ok(DecodeOutcome::Decoded(Event::Transfer(
                    BridgeTransferEvent {
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
                    },
                )))
            } else if log.topics[0] == packet_verified_topic0() {
                let event = decode_packet_verified(log)
                    .context("failed to decode LayerZeroPacketVerified")?;

                // Use same canonical hash: srcEid:nonce
                let message_hash = if event.src_eid > 0 && event.nonce > 0 {
                    Some(format!("{}:{}", event.src_eid, event.nonce))
                } else {
                    None
                };

                Ok(DecodeOutcome::Decoded(Event::Transfer(
                    BridgeTransferEvent {
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
                    },
                )))
            } else {
                Ok(DecodeOutcome::NotReported)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::abi::encode as abi_encode;
    use ethers::types::U256;

    const TOKEN_BRIDGE: &str = "3ee18b2214aff97000d974cf647e7c347e8fa585";
    const SEQUENCE: u64 = 42;
    /// 100 WETH at 8 decimals — the form the token bridge encodes into every payload.
    const WETH_EIGHT_DECIMALS: u64 = 10_000_000_000;
    /// The same 100 WETH at 18 decimals.
    const WETH_EIGHTEEN_DECIMALS: u128 = 100_000_000_000_000_000_000;

    fn bridge_address() -> Address {
        Address::from_slice(&hex::decode(TOKEN_BRIDGE).expect("valid hex"))
    }

    fn transfer_payload(amount: u64, to_chain: u16) -> Bytes {
        let mut payload = vec![0u8; 133];
        payload[0] = 1;
        let mut amount_bytes = [0u8; 32];
        U256::from(amount).to_big_endian(&mut amount_bytes);
        payload[1..33].copy_from_slice(&amount_bytes);
        payload[99..101].copy_from_slice(&to_chain.to_be_bytes());
        Bytes::from(payload)
    }

    /// `LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel)`
    fn lock_log(sequence: u64, payload: Bytes) -> Log {
        let mut sender_topic = [0u8; 32];
        sender_topic[12..].copy_from_slice(bridge_address().as_bytes());

        Log {
            address: bridge_address(),
            topics: vec![
                WormholeLogMessagePublished::signature(),
                H256::from(sender_topic),
            ],
            data: Bytes::from(abi_encode(&[
                Token::Uint(U256::from(sequence)),
                Token::Uint(U256::from(0u64)),
                Token::Bytes(payload.to_vec()),
                Token::Uint(U256::from(15u64)),
            ])),
            ..Default::default()
        }
    }

    /// `TransferRedeemed(uint16 indexed emitterChainId, bytes32 indexed emitterAddress, uint64 indexed sequence)`
    fn unlock_log(emitter_chain: u16, emitter: [u8; 32], sequence: u64) -> Log {
        let mut chain_topic = [0u8; 32];
        chain_topic[30..].copy_from_slice(&emitter_chain.to_be_bytes());
        let mut sequence_topic = [0u8; 32];
        sequence_topic[24..].copy_from_slice(&sequence.to_be_bytes());

        Log {
            address: bridge_address(),
            topics: vec![
                WormholeTransferRedeemed::signature(),
                H256::from(chain_topic),
                H256::from(emitter),
                H256::from(sequence_topic),
            ],
            data: Bytes::new(),
            ..Default::default()
        }
    }

    fn calldata_carrying(payload: &[u8]) -> Bytes {
        let mut calldata = vec![0xc6, 0x87, 0x85, 0x19]; // completeTransfer(bytes)
        calldata.extend_from_slice(&[0u8; 31]);
        calldata.push(32); // offset to the bytes argument
        calldata.extend_from_slice(&[0u8; 28]);
        calldata.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        calldata.extend_from_slice(payload);
        Bytes::from(calldata)
    }

    fn decode_transfer(outcome: DecodeOutcome) -> BridgeTransferEvent {
        match outcome {
            DecodeOutcome::Decoded(Event::Transfer(transfer)) => transfer,
            other => panic!("expected a decoded transfer, got {other:?}"),
        }
    }

    /// Both legs are decoded from inputs that share only the Wormhole message identity, so this
    /// is the test that would fail if padding, byte order, or amount scale drifted on one side.
    /// Before the payload-scale fix this produced 1e20 on the lock and 1e8 on the unlock.
    #[test]
    fn lock_and_unlock_of_one_weth_transfer_agree_on_hash_and_amount() {
        let lock = decode_transfer(
            decode(
                &lock_log(SEQUENCE, transfer_payload(WETH_EIGHT_DECIMALS, 1)),
                BridgeProtocol::Wormhole,
                "eip155:1".to_string(),
                "Ethereum".to_string(),
                format!("0x{TOKEN_BRIDGE}"),
                "lock".to_string(),
                1,
                1,
                H256::zero(),
                0,
                1,
                0,
                "0".to_string(),
                "0xtoken".to_string(),
                Some("WETH".to_string()),
                None,
            )
            .expect("lock decodes"),
        );

        let payload = transfer_payload(WETH_EIGHT_DECIMALS, 1);
        let (_, emitter) = wormhole_emitter(bridge_address(), 2);
        let emitter: [u8; 32] = hex::decode(&emitter)
            .expect("emitter hex")
            .try_into()
            .expect("32 bytes");
        let unlock = decode_transfer(
            decode(
                &unlock_log(2, emitter, SEQUENCE),
                BridgeProtocol::Wormhole,
                "eip155:1".to_string(),
                "Ethereum".to_string(),
                format!("0x{TOKEN_BRIDGE}"),
                "unlock".to_string(),
                2,
                2,
                H256::zero(),
                1,
                2,
                0,
                "0".to_string(),
                "0xtoken".to_string(),
                Some("WETH".to_string()),
                Some(&calldata_carrying(&payload)),
            )
            .expect("unlock decodes"),
        );

        assert_eq!(lock.direction, TransferDirection::Lock);
        assert_eq!(unlock.direction, TransferDirection::Unlock);
        assert_eq!(lock.message_hash, unlock.message_hash);
        assert_eq!(lock.amount, unlock.amount);
        assert_eq!(
            lock.amount,
            Decimal::from(BigInt::from(WETH_EIGHTEEN_DECIMALS).to_signed_bytes_be())
        );
    }

    #[test]
    fn unlock_without_calldata_is_reported_lost_rather_than_emitted_with_a_zero_amount() {
        let outcome = decode(
            &unlock_log(2, [7u8; 32], SEQUENCE),
            BridgeProtocol::Wormhole,
            "eip155:1".to_string(),
            "Ethereum".to_string(),
            format!("0x{TOKEN_BRIDGE}"),
            "unlock".to_string(),
            1,
            1,
            H256::zero(),
            0,
            1,
            0,
            "0".to_string(),
            "0xtoken".to_string(),
            None,
            None,
        )
        .expect("a missing VAA is data loss, not a decode error");

        match outcome {
            DecodeOutcome::DataLost(reason) => {
                assert!(
                    reason.contains("transaction input"),
                    "reason should name the missing calldata, got: {reason}"
                );
            }
            other => panic!("expected the unlock to be reported as lost, got {other:?}"),
        }
    }

    /// The core contract publishes for every Wormhole application. Those messages are expected,
    /// so they must not be reported as decode failures.
    #[test]
    fn message_from_another_wormhole_app_is_not_reported() {
        let mut other_sender = [0u8; 32];
        other_sender[12..].copy_from_slice([0x11u8; 20].as_slice());

        let log = Log {
            address: bridge_address(),
            topics: vec![
                WormholeLogMessagePublished::signature(),
                H256::from(other_sender),
            ],
            data: Bytes::from(abi_encode(&[
                Token::Uint(U256::from(SEQUENCE)),
                Token::Uint(U256::from(0u64)),
                Token::Bytes(transfer_payload(WETH_EIGHT_DECIMALS, 1).to_vec()),
                Token::Uint(U256::from(15u64)),
            ])),
            ..Default::default()
        };

        let outcome = decode(
            &log,
            BridgeProtocol::Wormhole,
            "eip155:1".to_string(),
            "Ethereum".to_string(),
            format!("0x{TOKEN_BRIDGE}"),
            "lock".to_string(),
            1,
            1,
            H256::zero(),
            0,
            1,
            0,
            "0".to_string(),
            "0xtoken".to_string(),
            None,
            None,
        )
        .expect("an unrelated application is not a decode error");

        assert!(matches!(outcome, DecodeOutcome::NotReported));
    }

    /// The Solana unlock path reads the emitter address out of a VAA as 32 raw bytes and
    /// hex-encodes them. This test locks that the EVM lock side produces the same zero-padded
    /// representation, so both decoders agree on the `message_hash` for the same transfer.
    /// A parallel assertion lives in `solana-ingester/src/posted_message.rs`.
    #[test]
    fn evm_emitter_left_pads_address_to_32_bytes_matching_vaa_format() {
        let (chain, emitter_hex) = wormhole_emitter(bridge_address(), 2);
        let hash = format!("{}:{}:{}", chain, emitter_hex, SEQUENCE);

        assert_eq!(
            hash,
            "2:0000000000000000000000003ee18b2214aff97000d974cf647e7c347e8fa585:42"
        );
    }
}
