pub use crate::config::BridgeProtocol;
use crate::rpc_retry::RetryableRpcClient;
use anyhow::{bail, Context, Result};
use apache_avro::Decimal;
use dex_ingester_common::{
    BridgeSupplyEvent, BridgeTransferEvent, Event, SupplyOperation, TransferDirection,
};
use num_bigint::BigInt;
use solana_sdk::pubkey::Pubkey;
use std::convert::TryInto;

fn u64_to_decimal(value: u64) -> Decimal {
    let big_int = BigInt::from(value);
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
    rpc_client: &RetryableRpcClient,
) -> Result<Event> {
    if data.is_empty() {
        bail!("empty instruction data");
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
    rpc_client: &RetryableRpcClient,
) -> Result<Event> {
    match discriminator {
        // TransferNative (5): outgoing lock. Amount and target_chain from instruction data.
        // Borsh layout: nonce:u32 | amount:u64 | fee:u64 | target_address:[u8;32] | target_chain:u16
        5 => {
            let amount = u64::from_le_bytes(
                data.get(4..12)
                    .context("instruction data too short for amount")?
                    .try_into()?,
            );
            let destination_chain = u16::from_le_bytes(
                data.get(52..54)
                    .context("instruction data too short for target_chain")?
                    .try_into()?,
            );
            let raw_amount = u64_to_decimal(amount);
            let normalized_amount = token_decimals
                .map(|d| normalize_to_18_decimals(raw_amount.clone(), d))
                .unwrap_or(raw_amount);

            Ok(Event::Transfer(BridgeTransferEvent {
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
                message_hash: None,
                sequence_number: None,
            }))
        }
        // TransferWrapped (4): outgoing burn of wrapped tokens on source chain.
        // Borsh layout: nonce:u32 | amount:u64 | fee:u64 | target_address:[u8;32] | target_chain:u16
        4 => {
            let amount = u64::from_le_bytes(
                data.get(4..12)
                    .context("instruction data too short for amount")?
                    .try_into()?,
            );
            let raw_amount = u64_to_decimal(amount);
            let normalized_amount = token_decimals
                .map(|d| normalize_to_18_decimals(raw_amount.clone(), d))
                .unwrap_or(raw_amount);

            Ok(Event::Supply(BridgeSupplyEvent {
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
                message_hash: None,
            }))
        }
        // CompleteNative (2): incoming unlock. Amount is in the VAA account, not instruction bytes.
        2 => {
            let (amount, message_hash, source_chain) = if let Some(vaa_pubkey) = vaa_account {
                match crate::vaa_parser::fetch_and_parse_vaa(rpc_client.inner(), vaa_pubkey).await {
                    Ok((header, transfer)) => {
                        let message_hash = format!(
                            "{}:{}:{}",
                            header.emitter_chain,
                            hex::encode(header.emitter_address),
                            header.sequence
                        );
                        let source_chain = format!("wormhole:{}", header.emitter_chain);
                        let normalized_amount = token_decimals
                            .map(|d| normalize_to_18_decimals(transfer.amount.clone(), d))
                            .unwrap_or(transfer.amount);
                        (normalized_amount, Some(message_hash), Some(source_chain))
                    }
                    Err(e) => {
                        tracing::warn!(
                            tx = %transaction_hash,
                            vaa = %vaa_pubkey,
                            "Failed to fetch or parse VAA: {:#}",
                            e
                        );
                        (u64_to_decimal(0), None, None)
                    }
                }
            } else {
                tracing::warn!(
                    tx = %transaction_hash,
                    "No VAA account provided for CompleteNative"
                );
                (u64_to_decimal(0), None, None)
            };

            Ok(Event::Transfer(BridgeTransferEvent {
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
                source_chain,
                message_hash,
                sequence_number: None,
            }))
        }
        // CompleteWrapped (3): incoming mint. Amount is in the VAA account, not instruction bytes.
        3 => {
            let (amount, message_hash, source_chain) = if let Some(vaa_pubkey) = vaa_account {
                match crate::vaa_parser::fetch_and_parse_vaa(rpc_client.inner(), vaa_pubkey).await {
                    Ok((header, transfer)) => {
                        let message_hash = format!(
                            "{}:{}:{}",
                            header.emitter_chain,
                            hex::encode(header.emitter_address),
                            header.sequence
                        );
                        let source_chain = format!("wormhole:{}", header.emitter_chain);
                        let normalized_amount = token_decimals
                            .map(|d| normalize_to_18_decimals(transfer.amount.clone(), d))
                            .unwrap_or(transfer.amount);
                        (normalized_amount, Some(message_hash), Some(source_chain))
                    }
                    Err(e) => {
                        tracing::warn!(
                            tx = %transaction_hash,
                            vaa = %vaa_pubkey,
                            "Failed to fetch or parse VAA: {:#}",
                            e
                        );
                        (u64_to_decimal(0), None, None)
                    }
                }
            } else {
                tracing::warn!(
                    tx = %transaction_hash,
                    "No VAA account provided for CompleteWrapped"
                );
                (u64_to_decimal(0), None, None)
            };

            Ok(Event::Supply(BridgeSupplyEvent {
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
                source_chain,
                message_hash,
            }))
        }
        _ => bail!("unknown Wormhole discriminator: {}", discriminator),
    }
}
