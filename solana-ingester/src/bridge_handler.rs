use crate::bridge_decoder::BridgeProtocol;
use crate::bridge_normalizer::BridgeNormalizer;
use crate::config::Token;
use crate::rpc_retry::RetryableRpcClient;
use anyhow::Result;
use dex_ingester_common::Event;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

pub struct BridgeHandler {
    normalizer: BridgeNormalizer,
    rpc_client: Arc<RetryableRpcClient>,
    tokens: Arc<BTreeMap<Pubkey, Token>>,
}

impl BridgeHandler {
    pub fn new(
        chain_id: String,
        chain_name: String,
        program_id: String,
        protocol: BridgeProtocol,
        rpc_client: Arc<RetryableRpcClient>,
        tokens: Arc<BTreeMap<Pubkey, Token>>,
    ) -> Self {
        let program_id = Pubkey::from_str(&program_id).expect("valid program_id");
        Self {
            normalizer: BridgeNormalizer::new(
                chain_id,
                chain_name,
                program_id,
                protocol,
                rpc_client.clone(),
            ),
            rpc_client,
            tokens,
        }
    }

    #[expect(dead_code)]
    pub fn program_id(&self) -> &Pubkey {
        self.normalizer.program_id()
    }

    pub async fn handle(&self, signature: Signature) -> Result<Vec<Event>> {
        let tx = self.rpc_client.get_transaction(signature).await?;

        let slot = tx.slot;
        let block_timestamp = tx.block_time.unwrap_or(0);

        let event_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let Some(meta) = tx.transaction.meta else {
            return Ok(vec![]);
        };

        if meta.err.is_some() {
            return Ok(vec![]);
        };

        let fee = meta.fee as i64;

        // Lock-side instructions do not carry the sequence: the core program assigns it when it
        // publishes the message, which is only visible in the transaction's logs.
        let program_id = *self.normalizer.program_id();
        let published = crate::posted_message::collect(
            &meta.log_messages.unwrap_or(Vec::new()),
            program_id.as_array(),
        );

        let Some(tx_data) = tx.transaction.transaction.decode() else {
            warn!("Failed to decode transaction: {}", signature);
            return Ok(vec![]);
        };

        // Extract account keys from the already-decoded transaction message
        let account_keys = tx_data.message.static_account_keys();

        // Extract token balances from meta's post_token_balances
        let post_token_balances: Vec<(Pubkey, u8)> = meta
            .post_token_balances
            .unwrap_or(Vec::new())
            .into_iter()
            .filter_map(|tb| {
                let mint = Pubkey::from_str(&tb.mint).ok()?;
                let decimals = tb.ui_token_amount.decimals;
                Some((mint, decimals))
            })
            .collect();

        let mut events = Vec::new();

        for (i, instruction) in tx_data.message.instructions().iter().enumerate() {
            let instruction_program_id = account_keys[instruction.program_id_index as usize];
            if instruction_program_id != *self.normalizer.program_id() {
                continue;
            }

            let instruction_data = instruction.data.as_slice();

            // Extract token mint based on discriminator
            let (token_mint, token_symbol, token_decimals) = if !instruction_data.is_empty() {
                let discriminator = instruction_data[0];
                let mint = match discriminator {
                    2 => account_keys.get(10).copied(), // CompleteNative: accounts[10]
                    3 => post_token_balances.first().map(|(m, _)| *m), // CompleteWrapped: postTokenBalances[].mint
                    4 => account_keys.get(4).copied(), // TransferWrapped: accounts[4]
                    5 => account_keys.get(3).copied(), // TransferNative: accounts[3]
                    _ => None,
                };

                let symbol = mint
                    .and_then(|m| self.tokens.get(&m))
                    .map(|t| t.symbol.as_str());
                let decimals = mint.and_then(|m| self.tokens.get(&m)).map(|t| t.decimals);
                (mint, symbol, decimals)
            } else {
                (None, None, None)
            };

            // For CompleteNative (2) and CompleteWrapped (3), VAA account is at accounts[1]
            let vaa_account = if !instruction_data.is_empty() {
                let discriminator = instruction_data[0];
                if discriminator == 2 || discriminator == 3 {
                    account_keys.get(1).copied()
                } else {
                    None
                }
            } else {
                None
            };

            // TransferNative (5) and TransferWrapped (4) are the outgoing legs; the message they
            // publish supplies the sequence and emitter identity.
            let target_chain = if instruction_data.len() >= 54 {
                u16::from_le_bytes([instruction_data[52], instruction_data[53]])
            } else {
                0
            };
            let published_message = match instruction_data.first() {
                Some(4) | Some(5) => crate::posted_message::select(&published, target_chain),
                _ => None,
            };

            match self
                .normalizer
                .normalize(
                    slot,
                    signature.to_string(),
                    i,
                    instruction_data,
                    block_timestamp,
                    event_timestamp,
                    fee,
                    token_mint.as_ref(),
                    token_symbol,
                    token_decimals,
                    vaa_account.as_ref(),
                    published_message,
                )
                .await
            {
                Ok(event) => {
                    events.push(event);
                }
                Err(e) => {
                    warn!("Failed to decode bridge instruction: {:#}", e);
                }
            }
        }

        Ok(events)
    }

    pub fn protocol(&self) -> BridgeProtocol {
        self.normalizer.protocol()
    }
}
