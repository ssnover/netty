use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io;
use std::io::{Read, Write};
use std::net::Ipv4Addr;

pub const HEADER_SIZE: usize = 20;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub version: u8,
    pub internet_header_len: u8,
    pub type_of_service: u8,
    pub datagram_len: u16,
    pub id: u16,
    pub control_flags: u8,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub proto: u8,
    pub checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

impl Header {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = io::Cursor::new(buf);
        let version_and_ihl = cursor.read_u8()?;
        let version = version_and_ihl & 0xF;
        let internet_header_len = version_and_ihl >> 4;
        let type_of_service = cursor.read_u8()?;
        let datagram_len = cursor.read_u16::<NetworkEndian>()?;
        let id = cursor.read_u16::<NetworkEndian>()?;
        let flags_and_frag_offset = cursor.read_u16::<NetworkEndian>()?;
        let control_flags = (flags_and_frag_offset & 0b111) as u8;
        let fragment_offset = flags_and_frag_offset >> 3;
        let time_to_live = cursor.read_u8()?;
        let proto = cursor.read_u8()?;
        let checksum = cursor.read_u16::<NetworkEndian>()?;
        let mut src_addr_octets = [0u8; 4];
        cursor.read_exact(&mut src_addr_octets)?;
        let src_addr = Ipv4Addr::from(src_addr_octets);
        let mut dst_addr_octets = [0u8; 4];
        cursor.read_exact(&mut dst_addr_octets)?;
        let dst_addr = Ipv4Addr::from(dst_addr_octets);

        Ok((Header {
            version,
            internet_header_len,
            type_of_service,
            datagram_len,
            id,
            control_flags,
            fragment_offset,
            time_to_live,
            proto,
            checksum,
            src_addr,
            dst_addr
        }, &buf[HEADER_SIZE..]))
    }
}