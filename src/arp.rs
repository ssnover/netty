use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io;
use std::io::{Read, Write};
use std::net::Ipv4Addr;

pub const HEADER_SIZE: usize = 8;

#[repr(u16)]
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
pub enum Opcode {
    ArpRequest = 1,
    ArpReply = 2,
    RarpRequest = 3,
    RarpReply = 4,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    hwtype: u16,
    protype: u16,
    hwsize: u8,
    prosize: u8,
    opcode: Opcode,
}

impl Header {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = std::io::Cursor::new(buf);
        let hwtype = cursor.read_u16::<NetworkEndian>()?;
        let protype = cursor.read_u16::<NetworkEndian>()?;
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
            &buf[..HEADER_SIZE],
        ))
    }

    pub fn encode(self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = std::io::Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.hwtype)?;
        cursor.write_u16::<NetworkEndian>(self.protype)?;
        cursor.write_u8(self.hwsize)?;
        cursor.write_u8(self.prosize)?;
        cursor.write_u16::<NetworkEndian>(self.opcode.to_u16().unwrap())?;
        Ok(HEADER_SIZE)
    }
}

pub enum Data {
    Ipv4(Ipv4Data),
}

pub struct Ipv4Data {
    smac: [u8; 6],
    sip: Ipv4Addr,
    dmac: [u8; 6],
    dip: Ipv4Addr,
}
