//! Recovery of Wormhole messages published during a token-bridge lock.
//!
//! A `TransferNative`/`TransferWrapped` instruction does not carry the sequence number: the
//! core program assigns it when it publishes the message, which happens after the token bridge
//! instruction returns. The published message is written to `program data` logs, so the
//! sequence — the piece needed to build the same `message_hash` the unlock side reads from the
//! VAA — is only available from the transaction's log messages.
//!
//! The published layout is Borsh-serialized and starts with fields the ingester does not need.
//! Rather than hardcode absolute offsets, parsing anchors on the emitter address: the 32 bytes
//! immediately followed by the payload. Sequence and emitter chain sit in front of it, matching
//! the field order used by the VAA header (`sequence`, `emitter_chain`, `emitter_address`,
//! `payload`), so the same triple is produced on both sides.

use base64::Engine;

const PROGRAM_DATA_PREFIX: &str = "Program data: ";

/// Minimum bytes needed to carry sequence (8), emitter chain (2) and the emitter address.
const PRE_EMITTER_LEN: usize = 10;

/// A message published by the Wormhole core program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostedMessage {
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl PostedMessage {
    /// Same format the unlock path builds from the VAA header, so both legs correlate.
    pub fn message_hash(&self) -> String {
        format!(
            "{}:{}:{}",
            self.emitter_chain,
            hex::encode(self.emitter_address),
            self.sequence
        )
    }

    /// Destination chain of a token-bridge Transfer payload, if this message carries one.
    /// Payload layout matches `vaa_parser::parse_token_bridge_transfer` (big-endian).
    pub fn token_transfer_destination(&self) -> Option<u16> {
        let payload = &self.payload;
        if payload.len() < 101 || payload[0] != 1 {
            return None;
        }
        Some(u16::from_be_bytes([payload[99], payload[100]]))
    }
}

/// Parses one `program data` log entry, returning the message emitted by `emitter`.
///
/// Returns `None` for entries from other programs and for messages with a different emitter,
/// which is what keeps governance and other-portal traffic out of the result.
pub fn parse_log_entry(entry: &str, emitter: &[u8; 32]) -> Option<PostedMessage> {
    let encoded = entry.strip_prefix(PROGRAM_DATA_PREFIX)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;

    let position = bytes.windows(emitter.len()).position(|w| w == emitter)?;
    if position < PRE_EMITTER_LEN {
        return None;
    }

    let emitter_chain = u16::from_be_bytes([bytes[position - 2], bytes[position - 1]]);
    let sequence = u64::from_be_bytes(bytes[position - 10..position - 2].try_into().ok()?);
    let payload = parse_borsh_bytes(&bytes[position + emitter.len()..]).unwrap_or_default();

    Some(PostedMessage {
        emitter_chain,
        emitter_address: *emitter,
        sequence,
        payload,
    })
}

/// Borsh `Vec<u8>`: u32 little-endian length followed by the bytes.
fn parse_borsh_bytes(tail: &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_le_bytes(tail.get(0..4)?.try_into().ok()?) as usize;
    let data = tail.get(4..4 + len)?;
    Some(data.to_vec())
}

/// Collects every message published by `emitter` in a transaction.
pub fn collect(log_messages: &[String], emitter: &[u8; 32]) -> Vec<PostedMessage> {
    log_messages
        .iter()
        .filter_map(|entry| parse_log_entry(entry, emitter))
        .collect()
}

/// Picks the message that belongs to a lock instruction targeting `target_chain`.
///
/// A transaction can publish more than one message (batched transfers), so the payload's
/// destination chain selects between them. Two messages to the same destination are
/// indistinguishable, and pairing either with this instruction would attribute a sequence that
/// belongs to the other transfer, so that case yields `None` instead of a guess.
pub fn select(messages: &[PostedMessage], target_chain: u16) -> Option<&PostedMessage> {
    let mut matching = messages
        .iter()
        .filter(|m| m.token_transfer_destination() == Some(target_chain));

    match (matching.next(), matching.next()) {
        (Some(message), None) => Some(message),
        _ => match messages {
            [single] => Some(single),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    const EMITTER: [u8; 32] = [7u8; 32];
    const OTHER_EMITTER: [u8; 32] = [9u8; 32];

    fn transfer_payload(destination_chain: u16) -> Vec<u8> {
        let mut payload = vec![0u8; 133];
        payload[0] = 1;
        payload[99..101].copy_from_slice(&destination_chain.to_be_bytes());
        payload
    }

    /// Serialized in the field order the core program uses: sequence, emitter chain, emitter
    /// address, payload — with leading fields the parser skips.
    fn logged_entry(
        emitter_chain: u16,
        sequence: u64,
        emitter: &[u8; 32],
        payload: &[u8],
    ) -> String {
        let mut bytes = vec![0u8; 42];
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&emitter_chain.to_be_bytes());
        bytes.extend_from_slice(emitter);
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        format!("Program data: {}", STANDARD.encode(bytes))
    }

    #[test]
    fn recovers_sequence_and_emitter_from_a_logged_message() {
        let entry = logged_entry(1, 42, &EMITTER, &transfer_payload(2));

        let message = parse_log_entry(&entry, &EMITTER).expect("message parsed");

        assert_eq!(message.sequence, 42);
        assert_eq!(message.emitter_chain, 1);
        assert_eq!(message.emitter_address, EMITTER);
        assert_eq!(message.token_transfer_destination(), Some(2));
        assert_eq!(
            message.message_hash(),
            format!("1:{}:42", hex::encode(EMITTER))
        );
    }

    #[test]
    fn ignores_entries_for_another_emitter() {
        let entry = logged_entry(1, 7, &OTHER_EMITTER, &transfer_payload(2));

        assert!(parse_log_entry(&entry, &EMITTER).is_none());
    }

    #[test]
    fn ignores_non_program_data_logs() {
        assert!(parse_log_entry("Program log: something else", &EMITTER).is_none());
    }

    #[test]
    fn selects_the_message_matching_the_target_chain() {
        let mut other_payload = transfer_payload(6);
        other_payload[0] = 1;
        let messages = vec![
            parse_log_entry(
                &logged_entry(1, 1, &EMITTER, &transfer_payload(2)),
                &EMITTER,
            )
            .unwrap(),
            parse_log_entry(&logged_entry(1, 2, &EMITTER, &other_payload), &EMITTER).unwrap(),
        ];

        let selected = select(&messages, 6).expect("match on destination chain");

        assert_eq!(selected.sequence, 2);
    }

    #[test]
    fn refuses_to_pick_between_two_messages_for_the_same_destination() {
        let first = parse_log_entry(
            &logged_entry(1, 1, &EMITTER, &transfer_payload(2)),
            &EMITTER,
        )
        .unwrap();
        let second = parse_log_entry(
            &logged_entry(1, 2, &EMITTER, &transfer_payload(2)),
            &EMITTER,
        )
        .unwrap();

        assert_eq!(select(&[first, second], 2), None);
    }

    #[test]
    fn falls_back_to_the_only_message_when_the_destination_is_unknown() {
        let message = PostedMessage {
            emitter_chain: 1,
            emitter_address: EMITTER,
            sequence: 5,
            payload: Vec::new(),
        };

        assert_eq!(select(std::slice::from_ref(&message), 2), Some(&message));
        assert_eq!(
            select(&[message.clone(), message.clone()], 2),
            None,
            "ambiguous candidates must not be guessed at"
        );
    }

    /// Wormhole encodes EVM addresses in VAAs as 20-byte addresses left-padded to 32 bytes.
    /// The EVM lock side produces the same padding via `wormhole_emitter`. Both decoders must
    /// agree on this format or every transfer produces a spurious LOCK_WITHOUT_UNLOCK pair.
    /// A parallel assertion lives in `evm-ingester/src/bridge_decoder.rs`.
    #[test]
    fn evm_padded_emitter_matches_evm_lock_hash_format() {
        let mut emitter_address = [0u8; 32];
        let bridge = hex::decode("3ee18b2214aff97000d974cf647e7c347e8fa585").unwrap();
        emitter_address[12..].copy_from_slice(&bridge);

        let message = PostedMessage {
            emitter_chain: 2,
            emitter_address,
            sequence: 42,
            payload: vec![],
        };

        assert_eq!(
            message.message_hash(),
            "2:0000000000000000000000003ee18b2214aff97000d974cf647e7c347e8fa585:42"
        );
    }
}
