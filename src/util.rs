use byteorder::{NetworkEndian, ReadBytesExt};
use std::io;

pub fn checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut cursor = io::Cursor::new(buf);

    let mut counter = buf.len();
    while counter >= 2 {
        sum += cursor.read_u16::<NetworkEndian>().unwrap() as u32;
        counter -= 2;
    }
    if counter == 1 {
        sum += cursor.read_u8().unwrap() as u32;
    }

    while sum > 0xffff {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let sum = sum as u16;
    sum ^ 0xffff
}

mod tests {
    #[test]
    fn calc_checksum() {
        use crate::util::*;
        let buf: [u8; 20] = [
            0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x04, 0x0a, 0x00, 0x00, 0x05,
        ];
        assert_eq!(checksum(&buf), 0xe4c0);
    }
}
