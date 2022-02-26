use std::io;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_tun::Tun;

mod arp;
mod eth;
mod icmpv4;
mod ipv4;
mod util;

pub const PACKET_SIZE: usize = 1500;
const ARP_TABLE_ENTRIES: usize = 32;

pub struct NettyStack {
    reader: ReadHalf<Tun>,
    writer: WriteHalf<Tun>,
    arp_translation_table: [Option<arp::CacheEntry>; ARP_TABLE_ENTRIES],
    netdev: NettyDevice<'static>,
}

impl NettyStack {
    pub fn new<'a>(if_name: &'a str) -> Result<Self, Box<dyn std::error::Error>> {
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
        self.writer.write_all(&buf[..idx + trailer_len]).await?;
        Ok(())
    }

    fn do_arp_lookup(&self, ip_addr: Ipv4Addr) -> Option<[u8; 6]> {
        if let Some(entry) = self.arp_translation_table.iter().find(|&&entry| {
            if let Some(entry) = entry {
                entry.ip == ip_addr
            } else {
                false
            }
        }) {
            Some(entry.unwrap().mac)
        } else {
            None
        }
    }

    async fn handle_ipv4(&mut self, packet: &[u8]) -> io::Result<()> {
        let (hdr, ip_payload) = ipv4::Header::decode(packet)?;
        if hdr.dst_addr == self.netdev.ipaddr {
            if hdr.proto == ipv4::ProtocolType::IcmpV4 {
                log::info!("Got a ping from {}", hdr.src_addr);
                self.handle_icmpv4(hdr, ip_payload).await?;
            }
        }
        Ok(())
    }

    async fn handle_icmpv4(&mut self, mut ip_hdr: ipv4::Header, ip_data: &[u8]) -> io::Result<()> {
        let (icmp_hdr, payload) = icmpv4::Header::decode(ip_data)?;
        if icmp_hdr.msg_type == icmpv4::MsgType::EchoRequest {
            let (echo_hdr, _payload) = icmpv4::EchoHeader::decode(payload)?;
            let echo_reply_hdr = icmpv4::EchoHeader {
                id: echo_hdr.id,
                seq: echo_hdr.seq,
            };
            let mut icmp_hdr = icmpv4::Header {
                msg_type: icmpv4::MsgType::EchoReply,
                code: 0,
                checksum: 0,
            };
            let mut buf = [0u8; icmpv4::HEADER_SIZE + icmpv4::ECHO_HEADER_SIZE];
            let _ = icmp_hdr.clone().encode(&mut buf)?;
            let _ = echo_reply_hdr
                .clone()
                .encode(&mut buf[icmpv4::HEADER_SIZE..])?;
            let checksum = util::checksum(&buf);
            icmp_hdr.checksum = checksum;

            ip_hdr.datagram_len = (icmpv4::ECHO_HEADER_SIZE
                + icmpv4::HEADER_SIZE
                + ipv4::HEADER_SIZE
                + _payload.len()) as u16;
            ip_hdr.checksum = 0;
            ip_hdr.dst_addr = ip_hdr.src_addr;
            ip_hdr.src_addr = self.netdev.ipaddr;
            if let Some(dmac) = self.do_arp_lookup(ip_hdr.dst_addr) {
                let mut buf = [0u8; 1500];
                let eth_hdr = eth::Header {
                    smac: self.netdev.hwaddr,
                    dmac,
                    ethertype: eth::Ethertype::IPv4,
                };
                let mut idx = 0;
                idx += eth_hdr.encode(&mut buf[idx..])?;
                idx += ip_hdr.encode(&mut buf[idx..])?;
                idx += icmp_hdr.encode(&mut buf[idx..])?;
                idx += echo_reply_hdr.encode(&mut buf[idx..])?;
                let mut cursor = io::Cursor::new(&mut buf[idx..]);
                let _ = cursor.write_all(_payload).await?;
                idx += _payload.len();
                self.writer.write_all(&buf[..idx]).await?;
            }
        }
        Ok(())
    }
}

pub struct NettyDevice<'a> {
    name: &'a str,
    hwaddr: [u8; 6],
    ipaddr: Ipv4Addr,
}
