use crate::config::Config;
use alloy::{
    network::EthereumWallet, providers::{ProviderBuilder, WsConnect}, rpc::client::ClientBuilder
};
use eyre::Result;
use std::sync::Arc;

pub type ProviderWrapper =  Arc<alloy::providers::fillers::FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider>>;

pub async fn get_provider(config: &Config, wallet: EthereumWallet) -> Result<ProviderWrapper> {
    let ws = WsConnect::new(config.ethereum.ws_endpoint.clone());
    let client = ClientBuilder::default().ws(ws).await?;
    let sync_provider: Arc<alloy::providers::fillers::FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider>> = Arc::new(ProviderBuilder::new().wallet(wallet).connect_client(client));
    Ok(sync_provider)
}
