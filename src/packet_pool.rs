use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq)]
enum PacketStatus {
    Empty,
    Allocated,
    WaitingForArp,
    ReadyToTransmit,
    ReadyToRead,
}

pub const PACKET_SIZE: usize = 1568;

pub struct Packet<'pool> {
    idx: usize,
    buf: *mut u8,
    _marker: PhantomData<&'pool ()>,
}

impl<'pool> Packet<'pool> {
    fn from_packet(idx: usize, pkt: &PacketInner<'pool>) -> Self {
        Packet { idx, buf: pkt.buf, _marker: PhantomData }
    }
}

#[derive(Clone, Copy)]
struct PacketInner<'pool> {
    status: PacketStatus,
    buf: *mut u8,
    _marker: PhantomData<&'pool ()>,
}

pub struct PacketPool<'pool, const PACKETS: usize = 0> {
    packets: Arc<Mutex<[PacketInner<'pool>; PACKETS]>>,
}

impl<'pool, const PACKETS: usize> PacketPool<'pool, PACKETS> {
    pub fn new(buffer: &'pool mut [u8]) -> io::Result<PacketPool<'pool, PACKETS>> {
        if buffer.len() % PACKET_SIZE != PACKETS {
            Err(io::ErrorKind::InvalidInput.into())
        } else {
            let pool = PacketPool {
                packets: Arc::new(Mutex::new(array_init::array_init::<_, _, PACKETS>(|idx| PacketInner {
                    status: PacketStatus::Empty,
                    buf: buffer[(idx * PACKET_SIZE)..((idx + 1) * PACKET_SIZE)].as_mut_ptr(),
                    _marker: PhantomData,
                }))),
            };

            Ok(pool)
        }
    }

    pub fn allocate(&self) -> Option<Packet<'pool>> {
        let mut lock = self.packets.lock().unwrap();
        for (idx, packet) in lock.iter_mut().enumerate() {
            if packet.status == PacketStatus::Empty {
                (*packet).status = PacketStatus::Allocated;
                return Some(Packet::from_packet(idx, &packet))
            }
        }
        None
    }

    fn release(&self, pkt: Packet, transmitted: bool) {
        let mut lock = self.packets.lock().unwrap();
        if lock[pkt.idx].status != PacketStatus::Allocated && lock[pkt.idx].status != PacketStatus::ReadyToTransmit {
            panic!("Somehow we got given a packet that we didn't allocate... O.o");
        } else {
            if transmitted {
                lock[pkt.idx].status = PacketStatus::Empty;
            } else {
                lock[pkt.idx].status = PacketStatus::ReadyToTransmit;
            }
        }
    }
}
