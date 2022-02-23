use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io;
use std::io::{Read, Write};
use std::net::Ipv4Addr;

pub const HEADER_SIZE: usize = 8;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum HwType {
    Ethernet = 0x0001,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ProtocolType {
    Ipv4 = 0x0800,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CacheEntry {
    pub hwtype: HwType,
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum Opcode {
    ArpRequest = 1,
    ArpReply = 2,
    RarpRequest = 3,
    RarpReply = 4,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub hwtype: HwType,
    pub protype: ProtocolType,
    pub hwsize: u8,
    pub prosize: u8,
    pub opcode: Opcode,
}

impl Header {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = std::io::Cursor::new(buf);
        let hwtype = match FromPrimitive::from_u16(cursor.read_u16::<NetworkEndian>()?) {
            Some(hwtype) => hwtype,
            None => return Err(io::ErrorKind::Unsupported.into()),
        };
        let protype = match FromPrimitive::from_u16(cursor.read_u16::<NetworkEndian>()?) {
            Some(protype) => protype,
            None => return Err(io::ErrorKind::Unsupported.into()),
        };
        let hwsize = cursor.read_u8()?;
        let prosize = cursor.read_u8()?;
        let opcode = match FromPrimitive::from_u16(cursor.read_u16::<NetworkEndian>()?) {
            Some(opcode) => opcode,
            None => return Err(io::ErrorKind::InvalidData.into()),
        };
        Ok((
            Header {
                hwtype,
                protype,
                hwsize,
                prosize,
                opcode,
            },
            &buf[HEADER_SIZE..],
        ))
    }

    pub fn encode(self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = std::io::Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.hwtype.to_u16().unwrap())?;
        cursor.write_u16::<NetworkEndian>(self.protype.to_u16().unwrap())?;
        cursor.write_u8(self.hwsize)?;
        cursor.write_u8(self.prosize)?;
        cursor.write_u16::<NetworkEndian>(self.opcode.to_u16().unwrap())?;
        Ok(HEADER_SIZE)
    }
}

pub struct Ipv4Data {
    pub smac: [u8; 6],
    pub sip: Ipv4Addr,
    pub dmac: [u8; 6],
    pub dip: Ipv4Addr,
}

impl Ipv4Data {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = std::io::Cursor::new(buf);
        let mut smac = [0u8; 6];
        cursor.read_exact(&mut smac)?;
        let mut sip_octets = [0u8; 4];
        cursor.read_exact(&mut sip_octets)?;
        let sip = Ipv4Addr::from(sip_octets);
        let mut dmac = [0u8; 6];
        cursor.read_exact(&mut dmac)?;
        let mut dip_octets = [0u8; 4];
        cursor.read_exact(&mut dip_octets)?;
        let dip = Ipv4Addr::from(dip_octets);
        Ok((
            Self {
                smac,
                sip,
                dmac,
                dip,
            },
            &buf[20..],
        ))
    }

    pub fn encode(self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = std::io::Cursor::new(buf);
        cursor.write_all(&self.smac)?;
        cursor.write_all(&self.sip.octets())?;
        cursor.write_all(&self.dmac)?;
        cursor.write_all(&self.dip.octets())?;
        Ok(20)
    }
}
