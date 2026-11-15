//! Conversion of transferred amounts to the single 18-decimal scale every consumer compares on.
//!
//! The scale an amount arrives in depends on where it was read, not on the token it belongs to:
//!
//! - Wormhole's token bridge converts every transfer to 8-decimal fixed point before encoding it
//!   into a payload, whatever the token's native scale. A `LogMessagePublished` payload on EVM and
//!   a VAA on either chain therefore carry 8 decimals, so `10^10` is the whole conversion.
//! - A chain-native instruction field (a Solana `TransferNative`/`TransferWrapped` amount) is in
//!   the token's own base units, so it converts by `10^(18 - decimals)`.
//!
//! Applying the token's decimals to a payload amount is the defect this module exists to prevent:
//! it scales WETH (18 decimals) by one and USDC (6) by `10^12`, putting the two legs of the same
//! transfer on scales that differ by ten orders of magnitude.

use apache_avro::Decimal;
use num_bigint::BigInt;

/// Wormhole's token bridge converts every amount to this many decimals before encoding it.
pub const WORMHOLE_AMOUNT_DECIMALS: u8 = 8;

const TARGET_DECIMALS: u8 = 18;

fn scale(amount: Decimal, digits: u32) -> Decimal {
    if digits == 0 {
        return amount;
    }
    let magnitude: Vec<u8> = amount.try_into().unwrap_or_else(|_| vec![0]);
    let scaled = BigInt::from_signed_bytes_be(&magnitude) * BigInt::from(10).pow(digits);
    Decimal::from(scaled.to_signed_bytes_be())
}

/// Scales an amount carried in a Wormhole payload (VAA or `LogMessagePublished`) to 18 decimals.
pub fn wormhole_payload_amount(amount: Decimal) -> Decimal {
    scale(
        amount,
        u32::from(TARGET_DECIMALS - WORMHOLE_AMOUNT_DECIMALS),
    )
}

/// Scales a chain-native base-unit amount to 18 decimals. A token with 18 or more decimals is
/// left unchanged.
pub fn native_amount(amount: Decimal, decimals: u8) -> Decimal {
    scale(amount, u32::from(TARGET_DECIMALS.saturating_sub(decimals)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(value: u128) -> Decimal {
        Decimal::from(BigInt::from(value).to_signed_bytes_be())
    }

    /// 100 tokens at 18 decimals — what every leg of a 100-token transfer must equal.
    const ONE_HUNDRED_TOKENS: u128 = 100_000_000_000_000_000_000;

    #[test]
    fn payload_amount_converts_from_eight_decimals_whatever_the_tokens_scale() {
        // Wormhole encodes 100 WETH (18 native decimals) and 100 USDC (6) as the same 1e10.
        assert_eq!(
            wormhole_payload_amount(dec(10_000_000_000)),
            dec(ONE_HUNDRED_TOKENS)
        );
    }

    #[test]
    fn native_amount_converts_from_the_tokens_own_decimals() {
        // 100 WETH on Solana is an 8-decimal mint; 100 USDC is 6.
        assert_eq!(
            native_amount(dec(10_000_000_000), 8),
            dec(ONE_HUNDRED_TOKENS)
        );
        assert_eq!(native_amount(dec(100_000_000), 6), dec(ONE_HUNDRED_TOKENS));
    }

    #[test]
    fn native_amount_leaves_eighteen_or_more_decimals_untouched() {
        assert_eq!(native_amount(dec(1_000), 18), dec(1_000));
        assert_eq!(native_amount(dec(1_000), 24), dec(1_000));
    }

    /// The failure mode worth pinning: an EVM lock and the Solana mint that completes it are read
    /// from two different places and must still agree on the amount.
    #[test]
    fn both_legs_of_one_transfer_land_on_the_same_amount() {
        let evm_lock = wormhole_payload_amount(dec(10_000_000_000));
        let solana_mint = native_amount(dec(10_000_000_000), 8);

        assert_eq!(evm_lock, solana_mint);
    }
}
