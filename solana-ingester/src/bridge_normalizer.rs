use crate::bridge_decoder::BridgeProtocol;
use crate::rpc_retry::RetryableRpcClient;
use anyhow::Result;
use dex_ingester_common::Event;
use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;

pub struct BridgeNormalizer {
    chain: String,
    chain_name: String,
    program_id: Pubkey,
    protocol: BridgeProtocol,
    rpc_client: Arc<RetryableRpcClient>,
}

impl BridgeNormalizer {
    #[expect(dead_code)]
    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    pub fn protocol(&self) -> BridgeProtocol {
        self.protocol
    }
}

impl BridgeNormalizer {
    pub fn new(
        chain: String,
        chain_name: String,
        program_id: Pubkey,
        protocol: BridgeProtocol,
        rpc_client: Arc<RetryableRpcClient>,
    ) -> Self {
        Self {
            chain,
            chain_name,
            program_id,
            protocol,
            rpc_client,
        }
    }

    pub async fn normalize(
        &self,
        slot: u64,
        tx_signature: String,
        instruction_index: usize,
        instruction_data: &[u8],
        block_timestamp: i64,
        event_timestamp: i64,
        fee: i64,
        token_mint: Option<&Pubkey>,
        token_symbol: Option<&str>,
        token_decimals: Option<u8>,
        vaa_account: Option<&Pubkey>,
    ) -> Result<Event> {
        let event_id = format!("{}:{}", tx_signature, instruction_index);

        crate::bridge_decoder::decode_instruction(
            &self.program_id,
            self.protocol,
            instruction_data,
            self.chain.clone(),
            self.chain_name.clone(),
            self.program_id.to_string(),
            event_id,
            slot as i64,
            block_timestamp,
            tx_signature,
            0,
            event_timestamp,
            fee,
            token_mint,
            token_symbol,
            token_decimals,
            vaa_account,
            &self.rpc_client,
        )
        .await
    }
}
