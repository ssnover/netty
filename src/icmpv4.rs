use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::io;
use std::io::{Read, Write};

pub const HEADER_SIZE: usize = 4;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum MsgType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub msg_type: MsgType,
    pub code: u8,
    pub checksum: u16,
}

impl Header {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = io::Cursor::new(buf);
        let msg_type = match FromPrimitive::from_u8(cursor.read_u8()?) {
            Some(msg_type) => msg_type,
            None => return Err(io::ErrorKind::Unsupported.into()),
        };
        let code = cursor.read_u8()?;
        let checksum = cursor.read_u16::<NetworkEndian>()?;
        Ok((
            Self {
                msg_type,
                code,
                checksum,
            },
            &buf[HEADER_SIZE..],
        ))
    }

    pub fn encode(self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = io::Cursor::new(buf);
        cursor.write_u8(self.msg_type.to_u8().unwrap())?;
        cursor.write_u8(self.code)?;
        cursor.write_u16::<NetworkEndian>(self.checksum)?;
        Ok(HEADER_SIZE)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EchoHeader {
    pub id: u16,
    pub seq: u16,
}

pub const ECHO_HEADER_SIZE: usize = 4;

impl EchoHeader {
    pub fn decode(buf: &[u8]) -> io::Result<(Self, &[u8])> {
        let mut cursor = io::Cursor::new(buf);
        let id = cursor.read_u16::<NetworkEndian>()?;
        let seq = cursor.read_u16::<NetworkEndian>()?;
        Ok((Self { id, seq }, &buf[ECHO_HEADER_SIZE..]))
    }

    pub fn encode(self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = io::Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.id)?;
        cursor.write_u16::<NetworkEndian>(self.seq)?;
        Ok(ECHO_HEADER_SIZE)
    }
}
