use alloy::providers::Provider;
use eyre::Result;
use futures::StreamExt;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*};

use crate::helpers::get_provider;

pub mod config;
pub mod helpers;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration with better error context
    let config =
        config::load_config().map_err(|e| eyre::eyre!("Failed to load configuration: {}", e))?;

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_line_number(true)
                .with_thread_ids(true),
        ) // Add thread info for debugging async issues
        .init();

    let provider =  get_provider(&config)
        .await
        .map_err(|e| eyre::eyre!("Failed to connect to Ethereum provider: {}", e))?;

    info!("Starting white hack detector...");


    // listen to new blocks and check for arbitrage opportunities
    let mut block_stream = provider.subscribe_full_blocks().into_stream().await?;

    while let Some(block) = block_stream.next().await {
        match block {
            Ok(block) => {
                info!("Received new full block: {:?}", block.header.number);
            }
            Err(e) => {
                error!("Failed to get block: {:?}", e);
            }
        }
    }
    Ok(())
}


