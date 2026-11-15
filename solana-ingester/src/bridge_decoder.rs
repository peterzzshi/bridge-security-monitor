pub use crate::config::BridgeProtocol;
use crate::rpc_retry::RetryableRpcClient;
use anyhow::{Context, Result};
use apache_avro::Decimal;
use dex_ingester_common::{
    native_amount, wormhole_payload_amount, BridgeSupplyEvent, BridgeTransferEvent, DecodeOutcome,
    Event, SupplyOperation, TransferDirection,
};
use num_bigint::BigInt;
use solana_sdk::pubkey::Pubkey;
use std::convert::TryInto;

fn u64_to_decimal(value: u64) -> Decimal {
    let big_int = BigInt::from(value);
    Decimal::from(big_int.to_signed_bytes_be())
}

// A TransferNative/TransferWrapped instruction body, with the discriminator already stripped:
// nonce:u32 | amount:u64 | fee:u64 | target_address:[u8;32] | target_chain:u16
const TRANSFER_AMOUNT_RANGE: std::ops::Range<usize> = 4..12;
const TRANSFER_TARGET_CHAIN_RANGE: std::ops::Range<usize> = 52..54;

fn transfer_amount(data: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(TRANSFER_AMOUNT_RANGE)
            .context("instruction data too short for amount")?
            .try_into()?,
    ))
}

fn transfer_target_chain(data: &[u8]) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(TRANSFER_TARGET_CHAIN_RANGE)
            .context("instruction data too short for target_chain")?
            .try_into()?,
    ))
}

/// Reads `target_chain` from instruction data that still carries its 1-byte discriminator, so
/// callers that hold the raw instruction (the handler, selecting a published message) and callers
/// that hold the stripped body cannot disagree on the offset.
pub(crate) fn transfer_target_chain_with_discriminator(data: &[u8]) -> Result<u16> {
    let body = data
        .get(1..)
        .context("instruction data is only a discriminator")?;
    transfer_target_chain(body)
}

pub async fn decode_instruction(
    program_id: &Pubkey,
    protocol: BridgeProtocol,
    data: &[u8],
    chain: String,
    chain_name: String,
    bridge_address: String,
    event_id: String,
    block_number: i64,
    block_timestamp: i64,
    transaction_hash: String,
    log_index: i32,
    event_timestamp: i64,
    fee: i64,
    token_mint: Option<&Pubkey>,
    token_symbol: Option<&str>,
    token_decimals: Option<u8>,
    vaa_account: Option<&Pubkey>,
    published_message: Option<&crate::posted_message::PostedMessage>,
    rpc_client: &RetryableRpcClient,
) -> Result<DecodeOutcome> {
    if data.is_empty() {
        // An instruction with no discriminator is not one of the four transfers.
        return Ok(DecodeOutcome::NotReported);
    }

    let discriminator = data[0];
    tracing::info!(
        protocol = protocol.as_str(),
        discriminator,
        tx = %transaction_hash,
        data = ?data,
        "raw Solana instruction"
    );
    decode_wormhole(
        discriminator,
        &data[1..],
        chain,
        chain_name,
        bridge_address,
        protocol,
        event_id,
        block_number,
        block_timestamp,
        transaction_hash,
        log_index,
        event_timestamp,
        fee,
        token_mint,
        token_symbol,
        token_decimals,
        vaa_account,
        published_message,
        rpc_client,
    )
    .await
    .with_context(|| {
        format!(
            "failed to decode {} instruction for program {}",
            protocol.as_str(),
            program_id
        )
    })
}

async fn decode_wormhole(
    discriminator: u8,
    data: &[u8],
    chain: String,
    chain_name: String,
    bridge_address: String,
    protocol: BridgeProtocol,
    event_id: String,
    block_number: i64,
    block_timestamp: i64,
    transaction_hash: String,
    log_index: i32,
    event_timestamp: i64,
    fee: i64,
    token_mint: Option<&Pubkey>,
    token_symbol: Option<&str>,
    token_decimals: Option<u8>,
    vaa_account: Option<&Pubkey>,
    published_message: Option<&crate::posted_message::PostedMessage>,
    rpc_client: &RetryableRpcClient,
) -> Result<DecodeOutcome> {
    match discriminator {
        // TransferNative (5): outgoing lock. Amount and target_chain from instruction data.
        // Borsh layout: nonce:u32 | amount:u64 | fee:u64 | target_address:[u8;32] | target_chain:u16
        5 => {
            let amount = transfer_amount(data)?;
            let destination_chain = transfer_target_chain(data)?;
            let raw_amount = u64_to_decimal(amount);
            // The instruction amount is in the mint's own base units, so it needs the token's
            // decimals to reach the shared 18-decimal scale. Without them the event is dropped
            // rather than emitted at a scale no other leg will match.
            let Some(decimals) = token_decimals else {
                return Ok(DecodeOutcome::DataLost(format!(
                    "no decimals configured for the lock token mint (tx {transaction_hash})"
                )));
            };
            let normalized_amount = native_amount(raw_amount, decimals);
            let message_hash = published_message.map(|m| m.message_hash());
            let sequence_number = published_message.map(|m| m.sequence as i64);

            Ok(DecodeOutcome::Decoded(Event::Transfer(
                BridgeTransferEvent {
                    event_id,
                    block_number,
                    block_timestamp,
                    transaction_hash,
                    log_index,
                    chain,
                    chain_name,
                    bridge_address,
                    protocol: protocol.as_str().to_string(),
                    direction: TransferDirection::Lock,
                    gas_used: fee,
                    gas_price: "0".to_string(),
                    event_timestamp,
                    sender: "".to_string(),
                    recipient: "".to_string(),
                    token: token_mint.map(|m| m.to_string()).unwrap_or_default(),
                    token_symbol: token_symbol.map(|s| s.to_string()),
                    amount: normalized_amount,
                    destination_chain: Some(format!("wormhole:{}", destination_chain)),
                    source_chain: None,
                    message_hash,
                    sequence_number,
                },
            )))
        }
        // TransferWrapped (4): outgoing burn of wrapped tokens on source chain.
        // Borsh layout: nonce:u32 | amount:u64 | fee:u64 | target_address:[u8;32] | target_chain:u16
        4 => {
            let amount = transfer_amount(data)?;
            let raw_amount = u64_to_decimal(amount);
            let Some(decimals) = token_decimals else {
                return Ok(DecodeOutcome::DataLost(format!(
                    "no decimals configured for the burn token mint (tx {transaction_hash})"
                )));
            };
            let normalized_amount = native_amount(raw_amount, decimals);

            Ok(DecodeOutcome::Decoded(Event::Supply(BridgeSupplyEvent {
                event_id,
                block_number,
                block_timestamp,
                transaction_hash,
                log_index,
                chain,
                chain_name,
                bridge_address,
                protocol: protocol.as_str().to_string(),
                operation: SupplyOperation::Burn,
                gas_used: fee,
                gas_price: "0".to_string(),
                event_timestamp,
                recipient: "".to_string(),
                wrapped_token: token_mint.map(|m| m.to_string()).unwrap_or_default(),
                wrapped_token_symbol: token_symbol.map(|s| s.to_string()),
                amount: normalized_amount,
                source_chain: None,
                message_hash: published_message.map(|m| m.message_hash()),
            })))
        }
        // CompleteNative (2): incoming unlock. Amount is in the VAA account, not instruction bytes.
        2 => {
            let Some(vaa_pubkey) = vaa_account else {
                return Ok(DecodeOutcome::DataLost(format!(
                    "no VAA account on CompleteNative unlock (tx {transaction_hash})"
                )));
            };
            let (header, transfer) = match crate::vaa_parser::fetch_and_parse_vaa(
                rpc_client.inner(),
                vaa_pubkey,
            )
            .await
            {
                Ok(parsed) => parsed,
                Err(e) => {
                    return Ok(DecodeOutcome::DataLost(format!(
                        "failed to fetch or parse VAA {vaa_pubkey} for unlock: {e:#}"
                    )))
                }
            };
            let message_hash = format!(
                "{}:{}:{}",
                header.emitter_chain,
                hex::encode(header.emitter_address),
                header.sequence
            );
            // VAA amounts are 8-decimal whatever the token, so no token decimals are involved.
            let amount = wormhole_payload_amount(transfer.amount);

            Ok(DecodeOutcome::Decoded(Event::Transfer(
                BridgeTransferEvent {
                    event_id,
                    block_number,
                    block_timestamp,
                    transaction_hash,
                    log_index,
                    chain,
                    chain_name,
                    bridge_address,
                    protocol: protocol.as_str().to_string(),
                    direction: TransferDirection::Unlock,
                    gas_used: fee,
                    gas_price: "0".to_string(),
                    event_timestamp,
                    sender: "".to_string(),
                    recipient: "".to_string(),
                    token: token_mint.map(|m| m.to_string()).unwrap_or_default(),
                    token_symbol: token_symbol.map(|s| s.to_string()),
                    amount,
                    destination_chain: None,
                    source_chain: Some(format!("wormhole:{}", header.emitter_chain)),
                    message_hash: Some(message_hash),
                    sequence_number: Some(header.sequence as i64),
                },
            )))
        }
        // CompleteWrapped (3): incoming mint. Amount is in the VAA account, not instruction bytes.
        3 => {
            let Some(vaa_pubkey) = vaa_account else {
                return Ok(DecodeOutcome::DataLost(format!(
                    "no VAA account on CompleteWrapped mint (tx {transaction_hash})"
                )));
            };
            let (header, transfer) = match crate::vaa_parser::fetch_and_parse_vaa(
                rpc_client.inner(),
                vaa_pubkey,
            )
            .await
            {
                Ok(parsed) => parsed,
                Err(e) => {
                    return Ok(DecodeOutcome::DataLost(format!(
                        "failed to fetch or parse VAA {vaa_pubkey} for mint: {e:#}"
                    )))
                }
            };
            let message_hash = format!(
                "{}:{}:{}",
                header.emitter_chain,
                hex::encode(header.emitter_address),
                header.sequence
            );
            // VAA amounts are 8-decimal whatever the token, so no token decimals are involved.
            let amount = wormhole_payload_amount(transfer.amount);

            Ok(DecodeOutcome::Decoded(Event::Supply(BridgeSupplyEvent {
                event_id,
                block_number,
                block_timestamp,
                transaction_hash,
                log_index,
                chain,
                chain_name,
                bridge_address,
                protocol: protocol.as_str().to_string(),
                operation: SupplyOperation::Mint,
                gas_used: fee,
                gas_price: "0".to_string(),
                event_timestamp,
                recipient: "".to_string(),
                wrapped_token: token_mint.map(|m| m.to_string()).unwrap_or_default(),
                wrapped_token_symbol: token_symbol.map(|s| s.to_string()),
                amount,
                source_chain: Some(format!("wormhole:{}", header.emitter_chain)),
                message_hash: Some(message_hash),
            })))
        }
        _ => Ok(DecodeOutcome::NotReported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 100 WETH on Solana is an 8-decimal mint.
    const TARGET_DECIMALS: u8 = 8;
    const WETH_BASE_UNITS: u64 = 10_000_000_000;
    /// The same 100 WETH at the 18 decimals every consumer compares on.
    const WETH_EIGHTEEN_DECIMALS: u128 = 100_000_000_000_000_000_000;

    /// Use a target address whose last two bytes are non-zero: reading `target_chain` at the
    /// wrong offset then yields a plausible-looking chain instead of a zero, which is how the
    /// original off-by-one went unnoticed.
    fn transfer_instruction(discriminator: u8, amount: u64, target_chain: u16) -> Vec<u8> {
        let mut body = vec![0u8; 54];
        body[0..4].copy_from_slice(&7u32.to_le_bytes());
        body[4..12].copy_from_slice(&amount.to_le_bytes());
        body[12..20].copy_from_slice(&0u64.to_le_bytes());
        body[20..52].copy_from_slice(&[0xAAu8; 32]);
        body[52..54].copy_from_slice(&target_chain.to_le_bytes());

        let mut instruction = vec![discriminator];
        instruction.extend_from_slice(&body);
        instruction
    }

    #[test]
    fn reads_amount_and_target_chain_from_the_stripped_body() {
        let instruction = transfer_instruction(5, WETH_BASE_UNITS, 2);
        let body = &instruction[1..];

        assert_eq!(transfer_amount(body).expect("amount"), WETH_BASE_UNITS);
        assert_eq!(transfer_target_chain(body).expect("target chain"), 2);
    }

    /// The handler holds the un-stripped instruction. Reading `[52..54]` there returns the tail of
    /// `target_address`, so the two callers must share one offset definition.
    #[test]
    fn unstripped_instruction_selects_the_same_target_chain() {
        let instruction = transfer_instruction(5, WETH_BASE_UNITS, 2);

        assert_eq!(
            transfer_target_chain_with_discriminator(&instruction).expect("target chain"),
            2
        );
        assert_eq!(
            u16::from_le_bytes([instruction[52], instruction[53]]),
            0x02AA,
            "the old offset must be demonstrably wrong on this fixture"
        );
    }

    #[test]
    fn eight_decimal_burn_amount_lands_on_the_same_scale_as_the_evm_lock() {
        let instruction = transfer_instruction(4, WETH_BASE_UNITS, 2);
        let amount = native_amount(u64_to_decimal(WETH_BASE_UNITS), TARGET_DECIMALS);

        assert_eq!(
            transfer_amount(&instruction[1..]).expect("amount"),
            WETH_BASE_UNITS
        );
        assert_eq!(
            amount,
            Decimal::from(BigInt::from(WETH_EIGHTEEN_DECIMALS).to_signed_bytes_be())
        );
    }

    #[test]
    fn truncated_body_reports_which_field_is_missing() {
        let body = vec![0u8; 20];

        let error = transfer_target_chain(&body).expect_err("too short");
        assert!(error.to_string().contains("target_chain"));
    }
}
