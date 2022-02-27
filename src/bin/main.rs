use futures::stream::TryStreamExt;
use netty::NettyStack;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .unwrap();
    const NUM_PACKETS: usize = 32;
    let mut packet_pool_buffer = [0u8; netty::PACKET_SIZE * NUM_PACKETS];

    let pool = netty::PacketPool::<NUM_PACKETS>::new(&mut packet_pool_buffer).unwrap();

    let if_name = "tap0";
    let mut netty = NettyStack::new(if_name)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    add_address(if_name, Ipv4Addr::new(10, 0, 0, 1).into(), handle).await?;

    netty.run().await?;
    Ok(())
}

async fn add_address(
    if_name: &str,
    addr: IpAddr,
    handle: rtnetlink::Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut links = handle
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();
    if let Some(link) = links.try_next().await? {
        handle
            .address()
            .add(link.header.index, addr, 24)
            .execute()
            .await?;
    }
    Ok(())
}

struct SimpleStdoutLogger;
static LOGGER: SimpleStdoutLogger = SimpleStdoutLogger;

impl log::Log for SimpleStdoutLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
