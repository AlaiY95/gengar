use dotenv::dotenv;
use ethers::providers::{Provider, Ws};
use tokio;

use gengar::common::constants::Env;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    setup_logger()?;

    // info!("Starting Gengar");
    println!("Starting Gengar");
    let ws = Ws::connect(config.wss_url.clone()).await?;
    let provider = Arc::new(Provider::new(ws));

    let (event_sender, _): (Sender<Event>, _) = broadcast::channel(512);

    let mut set = JoinSet::new();

    set.spawn(stream_new_blocks(provider.clone(), event_sender.clone()));

    set.spawn(handle_block_events(provider.clone(), event_sender.clone()));

    while let Some(res) = set.join_next().await {
        info!("{:?}", res);
    }

    let https_url = std::env::var("HTTPS_URL").expect("HTTPS_URL environment variable not found");

    println!("HTTPS_URL {}", https_url);

    Ok(())
}

async fn handle_block_events(
    provider: Arc<Provider<Ws>>,
    event_sender: Sender<Event>,
) -> Result<()> {
    Ok(())
}
