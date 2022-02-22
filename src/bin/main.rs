use netty::NettyStack;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut netty = NettyStack::new("tun1")?;
    netty.run().await?;
    Ok(())
}
