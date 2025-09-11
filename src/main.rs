use std::{ops::Add, str::FromStr, sync::Arc};

use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{Address, Bytes, U256, address},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{TransactionInput, TransactionRequest, mev::EthSendBundle},
    signers::{k256::elliptic_curve::consts::U2, local::PrivateKeySigner},
    sol,
};
use alloy_mev::{BundleSigner, EthMevProviderExt};
use eyre::Result;
use futures::StreamExt;
use once_cell::sync::Lazy;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::helpers::{ProviderWrapper, get_provider_http, get_provider_ws};

pub mod config;
pub mod helpers;

// Define constant addresses
const FUND_WALLET: Address = address!("0xd222623aFCbC3bE0f6EAD371655CeE832189EB8D"); 
const HACKED_ADDRESS: Address = address!("0x3c343da0759165f4a1c48fba4ca11c29a71a8846");
const CLAIM_CONTRACT_ADDRESS: Address = address!("0xe3F64a918a2007059d8b5cd083c2b7891927697e");
const LEVVA_TOKEN_ADDRESS: Address = address!("0x6243558a24CC6116aBE751f27E6d7Ede50ABFC76");
const SAFE_TRANSFER_ADDRESS: Address = address!("0x014F0E84E6f84E631A12b0b683618fF5D82DfaeD");
static TRANSFER_AMOUNT: Lazy<U256> = Lazy::new(|| {
    U256::from_str_radix("821600000000000000000000", 10).expect("Invalid TRANSFER_AMOUNT")
});


// todo work out exact time
// todo read through all logic
// todo add logic to also transfer from my wallet /after too?
// todo check if the hacker does anything in next couple of days
// Define Solidity interfaces using `sol!` macro
sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ILevvaAirdrop {
        event Claimed(address indexed user, uint256 amount);
        event Locked(address indexed user, uint64 lockedTill, uint256 amountWithBonus);
        event Released(address indexed user, uint256 amount);

        function claimed(address user) external view returns (uint256 amount);
        function locked(address user) external view returns (uint256 amount, uint64 lockedTill, bool released);
        function release() external;
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract IERC20 {
        function decimals() external view returns (uint8);
        function name() external view returns (string memory);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
        function transfer(address to, uint256 value) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Checks the locked status for a given user on the ILevvaAirdrop contract.
async fn check_locked_status<P: Provider>(
    provider: &P,
    user: Address,
    contract_address: Address,
) -> Result<ILevvaAirdrop::lockedReturn> {
    let contract = ILevvaAirdrop::new(contract_address, provider);
    let locked_status = contract
        .locked(user)
        .call()
        .await
        .map_err(|e| eyre::eyre!("Failed to call locked function: {}", e))?;
    Ok(locked_status)
}

/// Creates a bundle of release and transfer transactions.
async fn create_transaction_bundle(
    provider: &ProviderWrapper,
    signer: &PrivateKeySigner,
    balance: U256,
    airdrop_contract_address: Address,
    token_address: Address,
    to_address: Address,
) -> Result<Vec<Bytes>> {
    let nonce = provider
        .get_transaction_count(signer.address())
        .await
        .map_err(|e| eyre::eyre!("Failed to get nonce: {}", e))?;

    // Create release transaction
    let airdrop_contract = ILevvaAirdrop::new(airdrop_contract_address, provider);
    let release_tx = airdrop_contract
        .release()
        .from(signer.address())
        .nonce(nonce)
        .into_transaction_request();
    let encoded_release_tx = provider.encode_request(release_tx).await?;

    let erc20_contract = IERC20::new(token_address, provider);
    let transfer_tx = erc20_contract
        .transferFrom(HACKED_ADDRESS, to_address, balance)
        .from(signer.address())
        .nonce(nonce)
        .into_transaction_request();

    let encoded_transfer_tx = provider.encode_request(transfer_tx).await?;

    Ok(vec![encoded_release_tx, encoded_transfer_tx])
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_target(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .init();

    // Load configuration
    let config =
        config::load_config().map_err(|e| eyre::eyre!("Failed to load configuration: {}", e))?;

    // Create signer from private key
    let chris_signer = PrivateKeySigner::from_str(&config.ethereum.chris_priv_key)
        .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;
    let wallet = EthereumWallet::new(chris_signer.clone());

    // Initialize Ethereum provider with signer
    let provider_ws = get_provider_ws(&config, wallet.clone()).await?;
    let provider_http = get_provider_http(&config, wallet).await?;

    // Configure MEV bundle endpoints

    // Select which builders the bundle will be sent to
    let endpoints = provider_http
        .endpoints_builder()
        .beaverbuild()
        .titan(BundleSigner::flashbots(chris_signer.clone()))
        .flashbots(BundleSigner::flashbots(chris_signer.clone()))
        .build();

    info!("Starting white hack detector...");
    info!("TRANSFER_AMOUNT: {}", *TRANSFER_AMOUNT);

    // Subscribe to new blocks
    let mut block_stream = provider_ws
        .subscribe_blocks()
        .await
        .map_err(|e| eyre::eyre!("Failed to subscribe to blocks: {}", e))?
        .into_stream();

    // Process each block
    while let Some(block) = block_stream.next().await {
        info!("Received new block: {:?}", block.number);

        // Check locked status for HACKED_ADDRESS
        match check_locked_status(&provider_ws, HACKED_ADDRESS, CLAIM_CONTRACT_ADDRESS).await {
            Ok(locked_status) => {
                info!("Locked status for {}: {:?}", HACKED_ADDRESS, locked_status);
                let ILevvaAirdrop::lockedReturn {
                    amount,
                    lockedTill,
                    released,
                } = locked_status;

                info!(
                    "Amount: {}, Locked Till: {}, Released: {}",
                    amount, lockedTill, released
                );

                // If not released, attempt to bundle release and transfer
                if released {
                    info!("Tokens  released, attempting to bundle release and transfer...");
                    // Check token balance before creating bundle
                    let token_contract = IERC20::new(LEVVA_TOKEN_ADDRESS, &provider_ws);
                    let balance = token_contract.balanceOf(HACKED_ADDRESS).call().await?;

                    if balance != U256::from(0) {
                        match create_transaction_bundle(
                            &provider_http,
                            &chris_signer,
                            balance,
                            CLAIM_CONTRACT_ADDRESS,
                            LEVVA_TOKEN_ADDRESS,
                            SAFE_TRANSFER_ADDRESS,
                        )
                        .await
                        {
                            Ok(signed_txs) => {
                                let bundle = EthSendBundle {
                                    txs: signed_txs,
                                    block_number: block.number + 1,
                                    min_timestamp: None,
                                    max_timestamp: None,
                                    reverting_tx_hashes: vec![],
                                    replacement_uuid: None,
                                    dropping_tx_hashes: vec![],
                                    refund_percent: None,
                                    refund_recipient: None,
                                    refund_tx_hashes: vec![],
                                    extra_fields: Default::default(),
                                };
                                let responses =
                                    provider_http.send_eth_bundle(bundle, &endpoints).await;
                                info!("Bundle sent successfully: {:?}", responses);
                            }
                            Err(e) => error!("Failed to create transaction bundle: {:?}", e),
                        }
                    } else {
                        continue;
                    }
                }
            }
            Err(e) => {
                error!("Failed to check locked status: {:?}", e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use alloy::{primitives::U128, rpc::{client::ClientBuilder, types::state}};
    use eyre::Result;
    use reqwest::Url;

    type ProvHelper =  Arc<alloy::providers::fillers::FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::RootProvider>>;

    // not this must have anvil running on a fork.
    pub async fn get_provider_anvil() -> Result<ProvHelper> {
        let client = ClientBuilder::default()
            .http(Url::parse("http://127.0.0.1:8545").expect("Failed to parse URL"));
        let sync_provider = Arc::new(ProviderBuilder::new().connect_client(client));
        Ok(sync_provider)
    }
    

    #[tokio::test]
    async fn test_get_balance() -> Result<()> {
        let prov = get_provider_anvil().await?;

        let token_contract = IERC20::new(LEVVA_TOKEN_ADDRESS, &prov);
        let balance = token_contract.balanceOf(HACKED_ADDRESS).call().await?;

        dbg!(balance);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_lock() -> Result<()> {
        let prov = get_provider_anvil().await?;
        match check_locked_status(&prov, HACKED_ADDRESS, CLAIM_CONTRACT_ADDRESS).await {
            Ok(state) => {
                dbg!(state);
            },
            Err(_) => println!("failed to get state"),
        }
 
        Ok(())
    }

    #[tokio::test]
    async fn test_bundle() -> Result<()> {
        tracing_subscriber::fmt().init();
        // Load configuration
        let config =
            config::load_config().map_err(|e| eyre::eyre!("Failed to load configuration: {}", e))?;

        // Create signer from private key
        let chris_signer = PrivateKeySigner::from_str(&config.ethereum.chris_priv_key)
            .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;
        let wallet = EthereumWallet::new(chris_signer.clone());
        
        // Initialize Ethereum provider with signer
        let provider_ws = get_provider_ws(&config, wallet.clone()).await?;
        let provider_http = get_provider_http(&config, wallet).await?;
        // Select which builders the bundle will be sent to
        let endpoints = provider_http
            .endpoints_builder()
            .beaverbuild()
            .titan(BundleSigner::flashbots(chris_signer.clone()))
            .flashbots(BundleSigner::flashbots(chris_signer.clone()))
            .build();


        let block_number: u64 = provider_ws.get_block_number().await?;
    
        match create_transaction_bundle(
            &provider_ws,
            &chris_signer,
            *TRANSFER_AMOUNT,
            CLAIM_CONTRACT_ADDRESS,
            LEVVA_TOKEN_ADDRESS,
            SAFE_TRANSFER_ADDRESS,
        )
        .await
        {
            Ok(signed_txs) => {
                info!("Signed txs: {:?}", signed_txs);
                let bundle = EthSendBundle {
                    txs: signed_txs,
                    block_number: block_number + 1,
                    min_timestamp: None,
                    max_timestamp: None,
                    reverting_tx_hashes: vec![],
                    replacement_uuid: None,
                    dropping_tx_hashes: vec![],
                    refund_percent: None,
                    refund_recipient: None,
                    refund_tx_hashes: vec![],
                    extra_fields: Default::default(),
                };
                let responses =
                    provider_http.send_eth_bundle(bundle, &endpoints).await;
                    info!("Bundle sent successfully: {:?}", responses);
            }
            Err(e) => error!("Failed to create transaction bundle: {:?}", e),
        }
    
        Ok(())
    }

    #[tokio::test]
    async fn test_bundle_real() -> Result<()> {
        // Load configuration
        let config =
            config::load_config().map_err(|e| eyre::eyre!("Failed to load configuration: {}", e))?;

        // Create signer from private key
        let chris_signer = PrivateKeySigner::from_str(&config.ethereum.my_priv_key)
            .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;
        let wallet = EthereumWallet::new(chris_signer.clone());
        
        // Initialize Ethereum provider with signer
        let provider_ws = get_provider_ws(&config, wallet.clone()).await?;
        let provider_http = get_provider_http(&config, wallet).await?;

        // Configure MEV bundle endpoints

        // Select which builders the bundle will be sent to
        let endpoints = provider_http
            .endpoints_builder()
            .beaverbuild()
            .titan(BundleSigner::flashbots(chris_signer.clone()))
            .flashbots(BundleSigner::flashbots(chris_signer.clone()))
            .build();
        let block_number: u64 = provider_ws.get_block_number().await?;
    
        // Pay Vitalik using a MEV-Share bundle!
        let tx_1 = TransactionRequest::default()
            .to(HACKED_ADDRESS) // vitalik.eth
            .value(U256::from(1000000000));
            
        // Pay Vitalik using a MEV-Share bundle!
        let tx_2 = TransactionRequest::default()
            .to(SAFE_TRANSFER_ADDRESS) // vitalik.eth
            .value(U256::from(1000000000));
    
        // Broadcast the bundle to all builders setup above!
        let responses = provider_http
            .send_eth_bundle(
                EthSendBundle {
                    txs: vec![provider_http.encode_request(tx_1).await?,provider_http.encode_request(tx_2).await?],
                    block_number: block_number + 1,
                    min_timestamp: None,
                    max_timestamp: None,
                    reverting_tx_hashes: vec![],
                    replacement_uuid: None,
                    dropping_tx_hashes: vec![],
                    refund_percent: None,
                    refund_recipient: None,
                    refund_tx_hashes: vec![],
                    extra_fields: Default::default(),
                },
                &endpoints,
            )
            .await;
    
        println!("{responses:#?}");
        Ok(())
    }
}