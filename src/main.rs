use std::str::FromStr;

use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{address, Address, U256},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::mev::EthSendBundle,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_mev::EthMevProviderExt;
use eyre::Result;
use futures::StreamExt;
use once_cell::sync::Lazy;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;


pub mod helpers;
pub mod config;

// Define constant addresses
const HACKED_ADDRESS: Address = address!("0x3c343da0759165f4a1c48fba4ca11c29a71a8846");
const CLAIM_CONTRACT_ADDRESS: Address = address!("0xe3F64a918a2007059d8b5cd083c2b7891927697e");
const LEVVA_TOKEN_ADDRESS: Address = address!("0x6243558a24CC6116aBE751f27E6d7Ede50ABFC76");
const SAFE_TRANSFER_ADDRESS: Address = address!("0x014F0E84E6f84E631A12b0b683618fF5D82DfaeD");
static TRANSFER_AMOUNT: Lazy<U256> = Lazy::new(|| {
    U256::from_str_radix("821600000000000000000000", 10).expect("Invalid TRANSFER_AMOUNT")
});

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

/// Sends a standalone release transaction if needed.
async fn send_release_transaction<P: Provider>(
    provider: &P,
    signer: &PrivateKeySigner,
    contract_address: Address,
) -> Result<()> {
    let contract = ILevvaAirdrop::new(contract_address, provider);
    let tx = contract
        .release()
        .from(signer.address())
        // Optional: Customize gas settings
        // .gas_limit(100_000)
        // .max_fee_per_gas(U256::from(50_000_000_000)) // 50 gwei
        // .max_priority_fee_per_gas(U256::from(2_000_000_000)) // 2 gwei
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to send release transaction: {}", e))?;

    let receipt = tx
        .get_receipt()
        .await
        .map_err(|e| eyre::eyre!("Failed to get transaction receipt: {}", e))?;

    info!("Release transaction sent: {:?}", receipt.transaction_hash);
    Ok(())
}

/// Creates a bundle of release and transfer transactions.
async fn create_transaction_bundle<P: Provider>(
    provider: &P,
    signer: &PrivateKeySigner,
    airdrop_contract_address: Address,
    token_address: Address,
    to_address: Address,
) -> Result<Vec<Vec<u8>>> {
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
        // Optional: Customize gas settings
        // .gas_limit(100_000)
        // .max_fee_per_gas(U256::from(50_000_000_000)) // 50 gwei
        // .max_priority_fee_per_gas(U256::from(2_000_000_000)) // 2 gwei
        .into_transaction_request();


    // Create transfer transaction
    let token_contract = IERC20::new(token_address, provider);
    let transfer_tx = token_contract
        .transfer(to_address, *TRANSFER_AMOUNT)
        .from(signer.address())
        .nonce(nonce + U256::from(1))
        // Optional: Customize gas settings
        // .gas_limit(80_000)
        // .max_fee_per_gas(U256::from(50_000_000_000)) // 50 gwei
        // .max_priority_fee_per_gas(U256::from(2_000_000_000)) // 2 gwei
        .into_transaction_request();

    // Sign transactions
    let release_signed = signer
        .sign_transaction(&release_tx)
        .await
        .map_err(|e| eyre::eyre!("Failed to sign release transaction: {}", e))?;
    let transfer_signed = signer
        .sign_transaction(&transfer_tx)
        .await
        .map_err(|e|  eyre::eyre!("Failed to sign transfer transaction: {}", e))?;

    Ok(vec![release_signed, transfer_signed])
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
    let config = config::load_config().map_err(|e|  eyre::eyre!("Failed to load configuration: {}", e))?;

    // Create signer from private key
    let chris_signer = PrivateKeySigner::from_str(&config.ethereum.priv_key)
        .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;
    let wallet = EthereumWallet::new(chris_signer.clone());

    // Initialize Ethereum provider with signer
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_ws(WsConnect::new(config.ethereum.ws_endpoint)).await?;

    // Configure MEV bundle endpoints
    let endpoints = provider
        .endpoints_builder()
        .flashbots(chris_signer.clone())
        .beaverbuild()
        .build();

    info!("Starting white hack detector...");
    info!("TRANSFER_AMOUNT: {}", *TRANSFER_AMOUNT);

    // Subscribe to new blocks
    let mut block_stream = provider
        .subscribe_blocks()
        .await
        .map_err(|e| eyre::eyre!("Failed to subscribe to blocks: {}", e))?
        .into_stream();

    // Process each block
    while let Some(block) = block_stream.next().await {
        info!("Received new block: {:?}", block.number);

        // Check locked status for HACKED_ADDRESS
        match check_locked_status(&provider, HACKED_ADDRESS, CLAIM_CONTRACT_ADDRESS).await {
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
                if !released {
                    info!("Tokens not released, attempting to bundle release and transfer...");
                    // Check token balance before creating bundle
                    let token_contract = IERC20::new(LEVVA_TOKEN_ADDRESS, &provider);

                        match create_transaction_bundle(
                            &provider,
                            &chris_signer,
                            CLAIM_CONTRACT_ADDRESS,
                            LEVVA_TOKEN_ADDRESS,
                            SAFE_TRANSFER_ADDRESS,
                        )
                        .await
                        {
                            Ok(signed_txs) => {
                                let bundle = EthSendBundle {txs:signed_txs,block_number:block.header.number.unwrap_or(0)+1,min_timestamp:None,max_timestamp:None,reverting_tx_hashes:vec![],replacement_uuid:None, dropping_tx_hashes: todo!(), refund_percent: todo!(), refund_recipient: todo!(), refund_tx_hashes: todo!(), extra_fields: todo!() };
                                match provider.send_eth_bundle(bundle, &endpoints).await {
                                    Ok(responses) => {
                                        info!("Bundle sent successfully: {:?}", responses);
                                    }
                                    Err(e) => error!("Failed to send bundle: {:?}", e),
                                }
                            }
                            Err(e) => error!("Failed to create transaction bundle: {:?}", e),
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