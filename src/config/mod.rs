use dotenvy::dotenv;
use eyre::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ethereum: EthereumConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    pub rpc_endpoint: String,
    pub ws_endpoint: String,
    pub chain_id: u64,
}

pub fn load_config() -> Result<Config> {
    let _ = dotenv();

    let config = Config {
        ethereum: EthereumConfig {
            rpc_endpoint: std::env::var("RPC_URL")
                .map_err(|_| eyre::eyre!("RPC_ENDPOINT not set in .env"))?,
            ws_endpoint: std::env::var("WS_URL")
                .map_err(|_| eyre::eyre!("WS_ENDPOINT not set in .env"))?,
            chain_id: std::env::var("CHAIN_ID")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .map_err(|_| eyre::eyre!("Invalid CHAIN_ID"))?,
        },
    };

    Ok(config)
}
