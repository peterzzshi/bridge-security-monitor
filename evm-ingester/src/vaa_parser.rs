use anyhow::{bail, Context, Result};
use apache_avro::Decimal;
use ethers::types::Bytes;
use num_bigint::BigInt;

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
    pub token_address: [u8; 32],
    pub token_chain: u16,
}

/// Parse Wormhole TokenBridge Transfer payload from VAA bytes.
/// The VAA payload is the portion after the VAA header (guardianSetIndex, signatures, timestamp, nonce, emitterChain, emitterAddress, sequence, consistencyLevel).
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

    let token_address: [u8; 32] = payload[33..65]
        .try_into()
        .context("Failed to extract token address")?;

    let token_chain = u16::from_be_bytes([payload[65], payload[66]]);

    Ok(TokenBridgeTransfer {
        amount,
        token_address,
        token_chain,
    })
}

fn u256_to_decimal(bytes: &[u8; 32]) -> Decimal {
    let big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes);
    Decimal::from(big_int.to_signed_bytes_be())
}

/// Extract VAA bytes from Wormhole TokenBridge completeTransfer* calldata.
/// Multiple method signatures exist:
/// - completeTransfer(bytes) - 0xc6878519
/// - completeTransferWithPayload(bytes) - 0xc4eb0b1b
/// - completeTransferAndUnwrapETH(bytes) - 0xff200cde
///
/// All encode the VAA as the first (and often only) parameter.
pub fn extract_vaa_from_calldata(calldata: &Bytes) -> Result<Vec<u8>> {
    if calldata.len() < 4 {
        bail!("Calldata too short: {} bytes", calldata.len());
    }

    // ABI encoding: 4-byte method selector + 32-byte offset + 32-byte length + data
    // For a single bytes parameter, offset is always 0x20 (32)
    if calldata.len() < 68 {
        bail!(
            "Calldata too short for ABI-encoded bytes: {} bytes",
            calldata.len()
        );
    }

    let length_offset = 36; // Skip 4-byte selector + 32-byte offset
                            // Length is a u256 (32 bytes), but we only need the last 4 bytes as u32
    let length_start = length_offset + 28; // Read last 4 bytes of the 32-byte length field
    let length = u32::from_be_bytes([
        calldata[length_start],
        calldata[length_start + 1],
        calldata[length_start + 2],
        calldata[length_start + 3],
    ]) as usize;

    let data_offset = length_offset + 32;
    if calldata.len() < data_offset + length {
        bail!(
            "Calldata length mismatch: declared {} bytes, available {}",
            length,
            calldata.len() - data_offset
        );
    }

    Ok(calldata[data_offset..data_offset + length].to_vec())
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
        assert_eq!(result.token_chain, 1);
        assert_eq!(result.token_address, [0u8; 32]);
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

    #[test]
    fn extract_vaa_from_valid_calldata() {
        // Simulate completeTransfer(bytes) calldata
        let mut calldata = vec![0xc6, 0x87, 0x85, 0x19]; // Method selector
        calldata.extend_from_slice(&[0u8; 31]); // Offset high bytes
        calldata.push(32); // Offset = 0x20
        calldata.extend_from_slice(&[0u8; 31]); // Length high bytes
        calldata.push(10); // Length = 10
        calldata.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // VAA data

        let vaa = extract_vaa_from_calldata(&Bytes::from(calldata)).unwrap();
        assert_eq!(vaa, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn reject_short_calldata() {
        let calldata = vec![0xc6, 0x87, 0x85]; // Only 3 bytes
        let result = extract_vaa_from_calldata(&Bytes::from(calldata));
        assert!(result.is_err());
    }
}
