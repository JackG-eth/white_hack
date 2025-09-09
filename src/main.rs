use std::str::FromStr;

use alloy::{
    primitives::{address, Address, U256}, providers::Provider,signers::local::PrivateKeySigner, sol, };
use eyre::Result;
use futures::StreamExt;
use once_cell::sync::Lazy;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::helpers::get_provider;

pub mod config;
pub mod helpers;

const HACKED_ADDRESS: Address = address!("0x3c343da0759165f4a1c48fba4ca11c29a71a8846");
const CLAIM_CONTRACT_ADDRESS: Address = address!("0xe3F64a918a2007059d8b5cd083c2b7891927697e");
const SAFE_TRANSFER_ADDRESS: Address = address!("0x014F0E84E6f84E631A12b0b683618fF5D82DfaeD");
const LEVVA_TOKEN_ADDRESS: Address = address!("0x6243558a24CC6116aBE751f27E6d7Ede50ABFC76");
static TRANSFER_AMOUNT: Lazy<U256> =
    Lazy::new(|| U256::from_str_radix("821600000000000000000000", 10).expect("Invalid TRANSFER_AMOUNT"));


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

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration with better error context
    let config =
        config::load_config().map_err(|e| eyre::eyre!("Failed to load configuration: {}", e))?;

    let filter = EnvFilter::new("info");

    dbg!(*TRANSFER_AMOUNT);
    // Create signer from private key
    let signer = PrivateKeySigner::from_str(&config.ethereum.priv_key)
    .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_line_number(true)
                .with_thread_ids(true)
                .with_filter(filter),
        ) // Add thread info for debugging async issues
        .init();

    let provider = get_provider(&config)
        .await
        .map_err(|e| eyre::eyre!("Failed to connect to Ethereum provider: {}", e))?;

    info!("Starting white hack detector...");

    // listen to new blocks and check for arbitrage opportunities
    let mut block_stream = provider.subscribe_full_blocks().into_stream().await?;

    while let Some(block) = block_stream.next().await {
        match block {
            Ok(block) => {
                info!("Received new full block: {:?}", block.header.number);
                match check_locked_status(&provider, HACKED_ADDRESS, CLAIM_CONTRACT_ADDRESS).await {
                    Ok(locked_status) => {
                        info!("Locked status for {}: {:?}", HACKED_ADDRESS, locked_status);
                        // Access fields directly from the struct
                        let ILevvaAirdrop::lockedReturn {
                            amount,
                            lockedTill,
                            released,
                        } = locked_status;
                        
                        info!(
                            "Amount: {}, Locked Till: {}, Released: {}",
                            amount, lockedTill, released
                        );

                        // If not released, send release transaction
                        if released {
                            info!("Tokens not released, attempting to release...");
                            match send_release_transaction(&provider, &signer, CLAIM_CONTRACT_ADDRESS).await {
                                Ok(_) => info!("Release transaction successful"),
                                Err(e) => error!("Failed to release: {:?}", e),
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to check locked status: {:?}", e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to get block: {:?}", e);
            }
        }
    }
    Ok(())
}

async fn check_locked_status<P: Provider>(
    provider: &P,
    user: Address,
    contract_address: Address,
) -> Result<ILevvaAirdrop::lockedReturn> {
    // Create a contract instance
    let contract = ILevvaAirdrop::new(contract_address, provider);

    // Call the `locked` function
    let locked_status = contract
        .locked(user)
        .call()
        .await
        .map_err(|e| eyre::eyre!("Failed to call locked function: {}", e))?;

    Ok(locked_status)
}

/// Sends the release transaction for the ILevvaAirdrop contract.
async fn send_release_transaction<P: Provider>(
    provider: &P,
    signer: &PrivateKeySigner,
    contract_address: Address,
) -> Result<()> {
    let contract = ILevvaAirdrop::new(contract_address, provider);
    let tx = contract
        .release()
        .from(signer.address())
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


/// Transfers Levva tokens to the safe address.
async fn transfer_tokens<P: Provider>(
    provider: &P,
    signer: &PrivateKeySigner,
    token_address: Address,
    to_address: Address,
) -> Result<()> {
    let levva_contract = IERC20::new(token_address, provider);

    // Use `transfer` since tokens are held by the signer
    let tx = levva_contract
        .transfer(to_address, *TRANSFER_AMOUNT)
        .from(signer.address())
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to send transfer transaction: {}", e))?;

    let receipt = tx
        .get_receipt()
        .await
        .map_err(|e| eyre::eyre!("Failed to get transaction receipt: {}", e))?;

    info!("Token transfer sent: {:?}", receipt.transaction_hash);
    Ok(())
}
