use crate::bridge_decoder::BridgeProtocol;
use anyhow::{Context, Result};
use dex_ingester_common::Event;
use ethers::types::{Address, Log};

pub struct BridgeNormalizer {
    chain_id: String,
    bridge_address: String,
    protocol: BridgeProtocol,
}

impl BridgeNormalizer {
    pub fn bridge_address(&self) -> &str {
        &self.bridge_address
    }
}

impl BridgeNormalizer {
    pub fn new(chain_id: String, bridge_address: String, protocol: BridgeProtocol) -> Self {
        Self {
            chain_id,
            bridge_address,
            protocol,
        }
    }

    pub fn normalize(
        &self,
        log: Log,
        block_timestamp: i64,
        event_timestamp: i64,
        gas_used: i64,
        gas_price: String,
        token_address: Option<&Address>,
        token_symbol: Option<&str>,
        token_decimals: Option<u8>,
        transaction_input: Option<&ethers::types::Bytes>,
    ) -> Result<Event> {
        let block_number = log.block_number.context("log missing block number")?;
        let transaction_hash = log
            .transaction_hash
            .context("log missing transaction hash")?;
        let log_index = log.log_index.context("log missing log index")?;

        let event_id = format!("{:?}:{}", transaction_hash, log_index);

        crate::bridge_decoder::decode(
            &log,
            self.protocol,
            self.chain_id.clone(),
            "Ethereum".to_string(),
            self.bridge_address.clone(),
            event_id,
            block_number.as_u64() as i64,
            block_timestamp,
            transaction_hash,
            log_index.as_u32() as i32,
            event_timestamp,
            gas_used,
            gas_price,
            token_address
                .map(|addr| format!("{:?}", addr))
                .unwrap_or_default(),
            token_symbol.map(String::from),
            token_decimals,
            transaction_input,
        )
    }
}
