use anyhow::{bail, Context, Result};
use apache_avro::Decimal;
use num_bigint::BigInt;
use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;

use crate::blockchain::RpcClient;

/// Wormhole TokenBridge Transfer payload layout (all fields big-endian):
/// - payloadID: u8 (must be 1 for Transfer)
/// - amount: [u8; 32] (u256)
/// - tokenAddress: [u8; 32]
/// - tokenChain: u16
/// - to: [u8; 32]
/// - toChain: u16
/// - fee: [u8; 32] (u256)
#[derive(Debug)]
pub struct TokenBridgeTransfer {
    pub amount: Decimal,
}

/// Wormhole VAA header fields needed for message_hash construction.
#[derive(Debug)]
pub struct VaaHeader {
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
}

/// Parse Wormhole TokenBridge Transfer payload from VAA payload bytes.
pub fn parse_token_bridge_transfer(payload: &[u8]) -> Result<TokenBridgeTransfer> {
    if payload.len() < 133 {
        bail!(
            "TokenBridge Transfer payload too short: {} bytes (expected 133)",
            payload.len()
        );
    }

    let payload_id = payload[0];
    if payload_id != 1 {
        bail!(
            "Invalid payloadID: {} (expected 1 for Transfer)",
            payload_id
        );
    }

    let amount_bytes: [u8; 32] = payload[1..33]
        .try_into()
        .context("Failed to extract amount bytes")?;
    let amount = u256_to_decimal(&amount_bytes);

    Ok(TokenBridgeTransfer { amount })
}

fn u256_to_decimal(bytes: &[u8; 32]) -> Decimal {
    let big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes);
    Decimal::from(big_int.to_signed_bytes_be())
}

/// Fetch and parse Wormhole VAA account data from Solana RPC.
/// Returns both the VAA header (for message_hash) and the parsed payload.
///
/// VAA account layout:
/// - guardian_set_index: u32 (LE)
/// - signatures: variable length (len_signatures * 66 bytes)
/// - timestamp: u32 (BE)
/// - nonce: u32 (BE)
/// - emitter_chain: u16 (BE)
/// - emitter_address: [u8; 32]
/// - sequence: u64 (BE)
/// - consistency_level: u8
/// - payload: variable length
pub async fn fetch_and_parse_vaa(
    rpc_client: &Arc<RpcClient>,
    vaa_account: &Pubkey,
) -> Result<(VaaHeader, TokenBridgeTransfer)> {
    let rpc_client = Arc::clone(rpc_client);
    let vaa_account = *vaa_account;

    // Fetch account data in a blocking task since the RPC client is synchronous
    let account_data =
        tokio::task::spawn_blocking(move || rpc_client.get_account_data_sync(&vaa_account))
            .await
            .context("Task panicked while fetching VAA account")??;

    if account_data.len() < 57 {
        bail!(
            "VAA account data too short: {} bytes (minimum 57)",
            account_data.len()
        );
    }

    // Skip guardian_set_index (4 bytes)
    let mut offset = 4;

    // Skip signatures: len_signatures (1 byte) + (signature_index + signature) * len
    let len_signatures = account_data[offset] as usize;
    offset += 1 + (len_signatures * 66);

    if account_data.len() < offset + 51 {
        bail!(
            "VAA account data too short after signatures: {} bytes",
            account_data.len()
        );
    }

    // Parse header fields
    let _timestamp = u32::from_be_bytes([
        account_data[offset],
        account_data[offset + 1],
        account_data[offset + 2],
        account_data[offset + 3],
    ]);
    offset += 4;

    let _nonce = u32::from_be_bytes([
        account_data[offset],
        account_data[offset + 1],
        account_data[offset + 2],
        account_data[offset + 3],
    ]);
    offset += 4;

    let emitter_chain = u16::from_be_bytes([account_data[offset], account_data[offset + 1]]);
    offset += 2;

    let emitter_address: [u8; 32] = account_data[offset..offset + 32]
        .try_into()
        .context("Failed to extract emitter_address")?;
    offset += 32;

    let sequence = u64::from_be_bytes([
        account_data[offset],
        account_data[offset + 1],
        account_data[offset + 2],
        account_data[offset + 3],
        account_data[offset + 4],
        account_data[offset + 5],
        account_data[offset + 6],
        account_data[offset + 7],
    ]);
    offset += 8;

    let _consistency_level = account_data[offset];
    offset += 1;

    // Remaining bytes are the payload
    let payload = &account_data[offset..];
    let transfer = parse_token_bridge_transfer(payload)?;

    let header = VaaHeader {
        emitter_chain,
        emitter_address,
        sequence,
    };

    Ok((header, transfer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_transfer_payload() {
        let mut payload = vec![1u8]; // payloadID = 1
        payload.extend_from_slice(&[0u8; 31]); // amount high bytes
        payload.push(100); // amount = 100
        payload.extend_from_slice(&[0u8; 32]); // token address
        payload.extend_from_slice(&[0, 1]); // token chain = 1
        payload.extend_from_slice(&[0u8; 32]); // to address
        payload.extend_from_slice(&[0, 2]); // to chain = 2
        payload.extend_from_slice(&[0u8; 32]); // fee

        let result = parse_token_bridge_transfer(&payload).unwrap();
        assert_eq!(
            result.amount,
            Decimal::from(BigInt::from(100u8).to_signed_bytes_be()),
            "the transfer amount is read from bytes 1..33, ahead of the token fields"
        );
    }

    #[test]
    fn reject_invalid_payload_id() {
        let mut payload = vec![3u8]; // Invalid payloadID
        payload.extend_from_slice(&[0u8; 132]);

        let result = parse_token_bridge_transfer(&payload);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid payloadID"));
    }

    #[test]
    fn reject_short_payload() {
        let payload = vec![1u8; 50]; // Too short
        let result = parse_token_bridge_transfer(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }
}
