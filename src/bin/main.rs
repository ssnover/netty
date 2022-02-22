use futures::stream::TryStreamExt;
use netty::NettyStack;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let if_name = "tap0";
    let mut netty = NettyStack::new(if_name)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    add_address(if_name, Ipv4Addr::new(10, 0, 0, 1).into(), handle).await?;
    
    netty.run().await?;
    Ok(())
}

async fn add_address(if_name: &str, addr: IpAddr, handle: rtnetlink::Handle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut links = handle.link().get().match_name(if_name.to_string()).execute();
    if let Some(link) = links.try_next().await? {
        handle.address().add(link.header.index, addr, 24).execute().await?;
    }
    Ok(())
}