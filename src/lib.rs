use std::io;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_tun::Tun;

mod arp;
mod eth;
mod ipv4;

pub const PACKET_SIZE: usize = 1500;
const ARP_TABLE_ENTRIES: usize = 32;

pub struct NettyStack {
    reader: ReadHalf<Tun>,
    writer: WriteHalf<Tun>,
    arp_translation_table: [Option<arp::CacheEntry>; ARP_TABLE_ENTRIES],
    netdev: NettyDevice<'static>,
}

impl NettyStack {
    pub fn new<'a>(
        if_name: &'a str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tun = tokio_tun::TunBuilder::new()
            .name(if_name)
            .tap(true)
            .packet_info(false)
            .up()
            .try_build()?;
        let (reader, writer) = tokio::io::split(tun);
        Ok(Self {
            reader,
            writer,
            arp_translation_table: [None; ARP_TABLE_ENTRIES],
            netdev: NettyDevice {
                hwaddr: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ipaddr: Ipv4Addr::new(10, 0, 0, 2),
                name: "mock_dev",
            },
        })
    }

    pub async fn run(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 2048];
        loop {
            let n = self.reader.read(&mut buf).await?;
            log::info!("Got {} bytes", n);
            if let Ok((header, eth_payload)) = eth::Header::decode(&buf[..n]) {
                match header.ethertype {
                    eth::Ethertype::ARP => {
                        if let Err(err) = self.handle_arp(eth_payload).await {
                            log::error!("Error handling arp: {}", err);
                        }
                    }
                    eth::Ethertype::IPv4 => {
                        if let Err(err) = self.handle_ipv4(eth_payload).await {
                            log::error!("Error handling ip: {}", err);
                        }
                    }
                    _ => {
                        log::info!("Unhandled ethertype: {:?}", header.ethertype);
                    }
                }
            }
        }
    }

    async fn handle_arp(&mut self, packet: &[u8]) -> io::Result<()> {
        let (hdr, arp_payload) = arp::Header::decode(packet)?;
        if hdr.hwtype == arp::HwType::Ethernet {
            if hdr.protype == arp::ProtocolType::Ipv4 {
                let (arp_data, _remainder) = arp::Ipv4Data::decode(arp_payload)?;
                if let Some(Some(mut entry)) =
                    self.arp_translation_table
                        .into_iter()
                        .find(|&entry| match entry {
                            Some(entry) => entry.hwtype == hdr.hwtype && entry.ip == arp_data.sip,
                            None => false,
                        })
                {
                    // Update the ARP entry
                    entry.mac = arp_data.smac;
                } else {
                    // Insert a new entry
                    if let Some(position) = self
                        .arp_translation_table
                        .into_iter()
                        .position(|entry| entry.is_none())
                    {
                        self.arp_translation_table[position] = Some(arp::CacheEntry {
                            hwtype: hdr.hwtype,
                            ip: arp_data.sip,
                            mac: arp_data.smac,
                        });
                    } else {
                        log::error!("ARP table is full!");
                    }
                }

                // Is it an ARP request?
                if hdr.opcode == arp::Opcode::ArpRequest {
                    let reply_hdr = arp::Header {
                        hwtype: arp::HwType::Ethernet,
                        protype: arp::ProtocolType::Ipv4,
                        hwsize: 6,
                        prosize: 4,
                        opcode: arp::Opcode::ArpReply,
                    };
                    let reply_data = arp::Ipv4Data {
                        smac: self.netdev.hwaddr,
                        sip: self.netdev.ipaddr,
                        dmac: arp_data.smac,
                        dip: arp_data.sip,
                    };
                    self.write_arp_packet(reply_hdr, reply_data).await?;
                }
            }
        }
        Ok(())
    }

    async fn write_arp_packet(&mut self, hdr: arp::Header, data: arp::Ipv4Data) -> io::Result<()> {
        let mut buf = [0u8; 1500];
        let eth_hdr = eth::Header {
            smac: self.netdev.hwaddr,
            dmac: data.dmac,
            ethertype: eth::Ethertype::ARP,
        };
        let mut idx = eth_hdr.encode(&mut buf)?;
        idx += hdr.encode(&mut buf[idx..])?;
        idx += data.encode(&mut buf[idx..])?;
        log::info!("ARP packet len: {}", idx);
        let trailer_len = 18;
        self.writer.write_all(&buf[..idx+trailer_len]).await?;
        Ok(())
    }

    async fn handle_ipv4(&mut self, packet: &[u8]) -> io::Result<()> {
        let (hdr, _ip_payload) = ipv4::Header::decode(packet)?;
        log::info!("Got ipv4 message from: {}", hdr.src_addr);
        Ok(())
    }
}

pub struct NettyDevice<'a> {
    name: &'a str,
    hwaddr: [u8; 6],
    ipaddr: Ipv4Addr,
}
