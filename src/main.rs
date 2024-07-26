use dotenv::dotenv;
use tokio;

use alloy_network::AnyNetwork;
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use log::info;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::broadcast::{self, Sender};
use tokio::task::JoinSet;

use gengar::common::constants::Env;
use gengar::common::streams::Event;
use gengar::common::utils::setup_logger;
use gengar::strategies::strategy::strategy;

// #[tokio::main]
#[tokio::main(flavor = "current_thread")]
// async fn main() -> Result<()> {
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    setup_logger().unwrap();
    println!("Starting Gengar");

    let env = Env::new();

    let ws_connect = WsConnect {
        url: env.wss_url.clone(),
        auth: None,
    };

    info!("WebSocket connection established");

    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .with_recommended_fillers()
        .on_ws(ws_connect)
        .await?;

    info!("Provider initialized");

    let provider = Arc::new(provider);

    let (event_sender, _): (Sender<Event>, _) = broadcast::channel(512);

    let mut set = JoinSet::new();

    set.spawn(strategy(provider.clone(), event_sender.clone()));

    while let Some(res) = set.join_next().await {
        info!("{:?}", res);
    }

    Ok(())
}
