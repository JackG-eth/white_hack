use crate::config::Config;
use alloy::{
    network::EthereumWallet,
    providers::{ProviderBuilder, WsConnect},
    rpc::client::ClientBuilder,
    transports::http::Http,
};
use eyre::Result;
use reqwest::Url;
use std::sync::Arc;

pub type ProviderWrapper = Arc<
    alloy::providers::fillers::FillProvider<
        alloy::providers::fillers::JoinFill<
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
            alloy::providers::fillers::WalletFiller<EthereumWallet>,
        >,
        alloy::providers::RootProvider,
    >,
>;

pub async fn get_provider_ws(config: &Config, wallet: EthereumWallet) -> Result<ProviderWrapper> {
    let ws = WsConnect::new(config.ethereum.ws_endpoint.clone());
    let client = ClientBuilder::default().ws(ws).await?;
    let sync_provider: Arc<
        alloy::providers::fillers::FillProvider<
            alloy::providers::fillers::JoinFill<
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
                alloy::providers::fillers::WalletFiller<EthereumWallet>,
            >,
            alloy::providers::RootProvider,
        >,
    > = Arc::new(ProviderBuilder::new().wallet(wallet).connect_client(client));
    Ok(sync_provider)
}

pub async fn get_provider_http(config: &Config, wallet: EthereumWallet) -> Result<ProviderWrapper> {
    let client = ClientBuilder::default()
        .http(Url::parse(&config.ethereum.rpc_endpoint).expect("Failed to parse URL"));
    let sync_provider: Arc<
        alloy::providers::fillers::FillProvider<
            alloy::providers::fillers::JoinFill<
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
                alloy::providers::fillers::WalletFiller<EthereumWallet>,
            >,
            alloy::providers::RootProvider,
        >,
    > = Arc::new(ProviderBuilder::new().wallet(wallet).connect_client(client));
    Ok(sync_provider)
}
