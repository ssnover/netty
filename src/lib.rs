use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio_tun::Tun;

mod arp;
mod eth;

pub struct NettyStack {
    reader: ReadHalf<Tun>,
    writer: WriteHalf<Tun>,
}

impl NettyStack {
    pub fn new(if_name: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let tun = tokio_tun::TunBuilder::new()
            .name(if_name)
            .tap(false)
            .packet_info(false)
            .up()
            .try_build()?;
        let raw_fd = tun.as_raw_fd();
        let (reader, writer) = tokio::io::split(tun);
        // TODO: How on earth do I set the hwaddr? Seems like maybe the fd I'm using here is wrong...
        let mut sa_data = [0i8; 14];
        sa_data[0] = 1;
        sa_data[1] = 2;
        sa_data[2] = 3;
        sa_data[3] = 4;
        sa_data[4] = 5;
        sa_data[5] = 6;
        let sockaddr = libc::sockaddr {
            sa_data,
            sa_family: libc::ARPHRD_ETHER,
        };
        netdevice::set_hardware(raw_fd, "tun0", sockaddr).unwrap();
        Ok(Self { reader, writer })
    }

    pub async fn run(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 1024];
        loop {
            let n = self.reader.read(&mut buf).await?;
            if let Ok((header, _eth_payload)) = eth::Header::decode(&buf[..n]) {
                println!("Got {} bytes: {:?}", n, &buf[..n]);
                println!("Ethertype: {:?}", header.ethertype);
            }
        }
    }
}

pub struct NettyDevice<'a> {
    name: &'a str,
    hwaddr: [u8; 6],
    ipaddr: Ipv4Addr,
}
