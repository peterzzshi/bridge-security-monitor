use crate::bridge_decoder::BridgeProtocol;
use crate::bridge_normalizer::BridgeNormalizer;
use crate::config::Token;
use crate::rpc_retry::RetryableProvider;
use anyhow::{Context, Result};
use dex_ingester_common::DecodeOutcome;
use ethers::prelude::*;
use ethers::types::Log;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

const BLOCK_TIMESTAMP_CACHE_SIZE: usize = 128;

/// ERC20 Transfer event signature: keccak256("Transfer(address,address,uint256)")
const ERC20_TRANSFER_TOPIC: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

pub struct BridgeListener<P: Middleware> {
    normalizer: BridgeNormalizer,
    rpc: Arc<RetryableProvider<P>>,
    block_timestamps: Arc<RwLock<LruCache>>,
    tokens: Arc<BTreeMap<Address, Token>>,
}

/// Simple LRU cache with deterministic eviction policy
struct LruCache {
    cache: HashMap<U64, (i64, usize)>, // (timestamp, access_order)
    access_counter: usize,
    capacity: usize,
}

impl LruCache {
    fn new(capacity: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(capacity),
            access_counter: 0,
            capacity,
        }
    }

    fn get(&mut self, key: &U64) -> Option<i64> {
        if let Some((timestamp, access_order)) = self.cache.get_mut(key) {
            let ts = *timestamp;
            self.access_counter += 1;
            *access_order = self.access_counter;
            Some(ts)
        } else {
            None
        }
    }

    fn insert(&mut self, key: U64, timestamp: i64) {
        if self.cache.len() >= self.capacity && !self.cache.contains_key(&key) {
            // Evict least recently used entry
            if let Some(lru_key) = self
                .cache
                .iter()
                .min_by_key(|(_, (_, access_order))| access_order)
                .map(|(k, _)| *k)
            {
                self.cache.remove(&lru_key);
            }
        }

        self.access_counter += 1;
        self.cache.insert(key, (timestamp, self.access_counter));
    }
}

impl<P: Middleware + 'static> BridgeListener<P> {
    pub fn new(
        chain_id: String,
        bridge_address: String,
        protocol: BridgeProtocol,
        rpc: Arc<RetryableProvider<P>>,
        tokens: Arc<BTreeMap<Address, Token>>,
    ) -> Self {
        Self {
            normalizer: BridgeNormalizer::new(chain_id, bridge_address, protocol),
            rpc,
            block_timestamps: Arc::new(RwLock::new(LruCache::new(BLOCK_TIMESTAMP_CACHE_SIZE))),
            tokens,
        }
    }

    pub async fn process_log(&self, log: Log) -> Result<DecodeOutcome> {
        let block_number = log.block_number.context("log missing block number")?;
        let block_timestamp = self.fetch_block_timestamp(block_number).await?;

        let transaction_hash = log
            .transaction_hash
            .context("log missing transaction hash")?;

        let (gas_used, gas_price, token_address, transaction_input) =
            self.fetch_receipt_data(transaction_hash).await?;

        // Look up token metadata from config
        let token_symbol = token_address
            .as_ref()
            .and_then(|addr| self.tokens.get(addr))
            .map(|token| token.symbol.clone());

        let event_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or_default();

        self.normalizer
            .normalize(
                log,
                block_timestamp,
                event_timestamp,
                gas_used,
                gas_price,
                token_address.as_ref(),
                token_symbol.as_deref(),
                transaction_input.as_ref(),
            )
            .inspect_err(|e| {
                tracing::warn!(
                    bridge = %self.normalizer.bridge_address(),
                    tx = ?transaction_hash,
                    "Failed to normalize bridge log: {:#}",
                    e
                );
            })
    }

    async fn fetch_block_timestamp(&self, block_number: U64) -> Result<i64> {
        // Fast path: read lock for cache hit
        {
            let mut cache = self.block_timestamps.write().await;
            if let Some(timestamp) = cache.get(&block_number) {
                return Ok(timestamp);
            }
        }

        // Slow path: fetch from RPC
        let block = self
            .rpc
            .get_block(block_number)
            .await
            .context("failed to fetch block")?
            .context("block not found")?;
        let timestamp = block.timestamp.as_u64() as i64;

        // Write lock to insert
        {
            let mut cache = self.block_timestamps.write().await;
            cache.insert(block_number, timestamp);
        }

        Ok(timestamp)
    }

    /// Fetches the transaction receipt from RPC and extracts gas data plus the token
    /// address from the first ERC20 Transfer log. The receipt is already fetched for gas
    /// data, so token address extraction is free — no separate Etherscan call needed.
    /// Also fetches the transaction input calldata for VAA parsing in unlock operations.
    async fn fetch_receipt_data(
        &self,
        transaction_hash: ethers::types::H256,
    ) -> Result<(i64, String, Option<H160>, Option<ethers::types::Bytes>)> {
        let receipt = self
            .rpc
            .get_transaction_receipt(transaction_hash)
            .await
            .context("failed to fetch transaction receipt")?
            .context("receipt not found")?;

        let gas_used = receipt.gas_used.map(|g| g.as_u64() as i64).unwrap_or(0);
        let gas_price = receipt
            .effective_gas_price
            .map(|p| p.to_string())
            .unwrap_or_else(|| "0".to_string());

        let token_address = receipt
            .logs
            .iter()
            .find(|log| log.topics.first() == Some(&ERC20_TRANSFER_TOPIC))
            .map(|log| log.address);

        // Fetch transaction input for VAA parsing
        let transaction_input = self
            .rpc
            .inner()
            .get_transaction(transaction_hash)
            .await
            .context("failed to fetch transaction")?
            .map(|tx| tx.input);

        Ok((gas_used, gas_price, token_address, transaction_input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_cache_evicts_least_recently_used() {
        let mut cache = LruCache::new(3);

        cache.insert(U64::from(1), 100);
        cache.insert(U64::from(2), 200);
        cache.insert(U64::from(3), 300);

        // Access block 1 to make it recently used
        assert_eq!(cache.get(&U64::from(1)), Some(100));

        // Insert block 4, should evict block 2 (least recently used)
        cache.insert(U64::from(4), 400);

        assert_eq!(cache.get(&U64::from(1)), Some(100)); // Still present
        assert_eq!(cache.get(&U64::from(2)), None); // Evicted
        assert_eq!(cache.get(&U64::from(3)), Some(300)); // Still present
        assert_eq!(cache.get(&U64::from(4)), Some(400)); // Newly inserted
    }

    #[test]
    fn lru_cache_updates_access_order_on_get() {
        let mut cache = LruCache::new(2);

        cache.insert(U64::from(1), 100);
        cache.insert(U64::from(2), 200);

        // Access block 1
        cache.get(&U64::from(1));

        // Insert block 3, should evict block 2 (not block 1, which was just accessed)
        cache.insert(U64::from(3), 300);

        assert_eq!(cache.get(&U64::from(1)), Some(100));
        assert_eq!(cache.get(&U64::from(2)), None);
        assert_eq!(cache.get(&U64::from(3)), Some(300));
    }

    #[test]
    fn lru_cache_does_not_evict_when_reinserting_existing_key() {
        let mut cache = LruCache::new(2);

        cache.insert(U64::from(1), 100);
        cache.insert(U64::from(2), 200);

        // Reinsert block 1 with new timestamp
        cache.insert(U64::from(1), 150);

        // Should not have evicted anything
        assert_eq!(cache.get(&U64::from(1)), Some(150));
        assert_eq!(cache.get(&U64::from(2)), Some(200));
    }
}
