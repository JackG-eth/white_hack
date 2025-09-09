use crate::config::Config;
use alloy::{
    providers::{ProviderBuilder, WsConnect},
    rpc::client::ClientBuilder,
};
use eyre::Result;
use std::sync::Arc;

pub type ProviderWrapper = Arc<
    alloy::providers::fillers::FillProvider<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::RootProvider,
    >,
>;

pub async fn get_provider(config: &Config) -> Result<ProviderWrapper> {
    let ws = WsConnect::new(config.ethereum.ws_endpoint.clone());
    let client = ClientBuilder::default().ws(ws).await?;
    let sync_provider = Arc::new(ProviderBuilder::new().connect_client(client));
    Ok(sync_provider)
}
