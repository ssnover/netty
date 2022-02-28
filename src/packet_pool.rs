use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

#[macro_export]
macro_rules! crate_static_pool {
    ($num_packets:literal) => {{
        let mut buf = std::boxed::Box::new([0u8; netty::PACKET_SIZE * $num_packets]);
        let mut buf = std::boxed::Box::leak(buf);
        netty::PacketPool::<$num_packets>::new(buf).unwrap()
    }};
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum PacketStatus {
    /// This slot in the packet pool is ready to be used
    Empty,
    /// This slot has been given to the caller and has not been returned
    Allocated,
    /// This packet is waiting on an ARP packet for more information
    WaitingForArp,
    /// This packet can be processed for writing to the network
    ReadyToTransmit,
    /// This packet can be read into a buffer and given to the user
    ReadyToRead,
}

pub const PACKET_SIZE: usize = 1568;

/// A wrapper around access to information about a packet in the packetpool.
/// * `idx` - The index of the packet in the pool
/// * `buf` - A pointer into the wider pool aligned on the beginning of the packet.
/// * `pool` - A reference back to the pool the packet came from.
pub struct Packet<'buf, 'pool, const SIZE: usize> {
    idx: usize,
    buf: *mut u8,
    used_bytes: usize,
    pool: &'pool PacketPool<'buf, SIZE>,
}

impl<'buf, 'pool, const SIZE: usize> Packet<'buf, 'pool, SIZE> {
    fn from_packet(
        idx: usize,
        pkt: &PacketInner<'buf>,
        pool: &'pool PacketPool<'buf, SIZE>,
    ) -> Self {
        Packet {
            idx,
            buf: pkt.buf,
            used_bytes: pkt.used_bytes,
            pool,
        }
    }

    pub fn capacity(&self) -> usize {
        PACKET_SIZE
    }

    pub fn write_data(&mut self, idx: usize, buf: &[u8]) -> io::Result<()> {
        if idx + buf.len() > PACKET_SIZE {
            Err(std::io::ErrorKind::InvalidInput.into())
        } else {
            // No need to do min here since we're pre-checking the buffer size
            unsafe {
                self.buf.copy_from(buf.as_ptr(), buf.len());
            }
            self.used_bytes = std::cmp::max(self.used_bytes, idx + buf.len());
            Ok(())
        }
    }

    pub fn read_data(self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            self.buf
                .copy_to(buf.as_mut_ptr(), std::cmp::min(buf.len(), PACKET_SIZE));
        }
        if buf.len() < PACKET_SIZE {
            Err(std::io::ErrorKind::UnexpectedEof.into())
        } else {
            Ok(self.used_bytes)
        }
    }
}

impl<'buf, 'pool, const SIZE: usize> Drop for Packet<'buf, 'pool, SIZE> {
    fn drop(&mut self) {
        self.pool.release(self.idx);
    }
}

/// This is the interal packet representation which tracks the packet's status
/// and can be copied as necessary. Don't let library callers have something
/// that can be copied since we've got a pointer into the buffer
#[derive(Clone, Copy)]
struct PacketInner<'buf> {
    status: PacketStatus,
    buf: *mut u8,
    used_bytes: usize,
    _marker: PhantomData<&'buf ()>,
}

unsafe impl<'buf> Send for PacketInner<'buf> {
    
}

/// Maintains the buffer of the packet pool and gives access to free packets
pub struct PacketPool<'buf, const PACKETS: usize> {
    packets: Arc<Mutex<[PacketInner<'buf>; PACKETS]>>,
}

impl<'pool, 'buf, const PACKETS: usize> PacketPool<'buf, PACKETS> {
    pub fn new(buffer: &'buf mut [u8]) -> io::Result<PacketPool<'buf, PACKETS>> {
        if buffer.len() != PACKETS * PACKET_SIZE {
            log::error!("Buffer provided was not the correct size");
            Err(io::ErrorKind::InvalidInput.into())
        } else {
            // Iterates over the buffer and gives pointers to evenly spaced indexes to where
            // packets should be located in the buffer
            let pool = PacketPool {
                packets: Arc::new(Mutex::new(array_init::array_init::<_, _, PACKETS>(|idx| {
                    PacketInner {
                        status: PacketStatus::Empty,
                        buf: buffer[(idx * PACKET_SIZE)..((idx + 1) * PACKET_SIZE)].as_mut_ptr(),
                        used_bytes: 0,
                        _marker: PhantomData,
                    }
                }))),
            };

            Ok(pool)
        }
    }

    /// Checks the packet pool for an unused packet slot and returns one if its available.
    pub fn allocate(&'pool self) -> Option<Packet<'buf, 'pool, PACKETS>> {
        let mut lock = self.packets.lock().unwrap();
        for (idx, packet) in lock.iter_mut().enumerate() {
            if packet.status == PacketStatus::Empty {
                (*packet).status = PacketStatus::Allocated;
                return Some(Packet::from_packet(idx, &packet, self));
            }
        }
        None
    }

    /// Returns a packet to the pool and out of control of client code
    /// * `pkt_idx` - Index of the packet in the pool
    fn release(&self, pkt_idx: usize) {
        let mut lock = self.packets.lock().unwrap();
        lock[pkt_idx].status = if lock[pkt_idx].status == PacketStatus::Allocated {
            // User allocated a packet and then didn't send it
            log::warn!("Packet allocated, but dropped without sending");
            PacketStatus::Empty
        } else {
            PacketStatus::ReadyToTransmit
        }
    }
}
