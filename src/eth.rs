use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io;
use std::io::{Read, Write};

pub const HEADER_SIZE: usize = 14;

#[repr(u16)]
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
pub enum Ethertype {
    IPv4 = 0x0800,
    ARP = 0x0806,
    RARP = 0x8035,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub dmac: [u8; 6],
    pub smac: [u8; 6],
    pub ethertype: Ethertype,
}

impl Header {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = std::io::Cursor::new(buf);
        let mut dmac = [0u8; 6];
        cursor.read_exact(&mut dmac)?;
        let mut smac = [0u8; 6];
        cursor.read_exact(&mut smac)?;
        let raw_ethertype = cursor.read_u16::<NetworkEndian>()?;
        let ethertype = match FromPrimitive::from_u16(raw_ethertype) {
            Some(ethertype) => ethertype,
            None => return Err(io::ErrorKind::Unsupported.into()),
        };
        Ok((
            Header {
                dmac,
                smac,
                ethertype,
            },
            &buf[HEADER_SIZE..],
        ))
    }

    pub fn encode(self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = std::io::Cursor::new(buf);
        cursor.write_all(&self.dmac)?;
        cursor.write_all(&self.smac)?;
        cursor.write_u16::<NetworkEndian>(self.ethertype.to_u16().unwrap())?;
        Ok(HEADER_SIZE)
    }
}
