use std::{io, mem, net::Ipv4Addr};

use libc::{
    bind, in_addr, recvfrom, sendto, sockaddr, sockaddr_in, socket, AF_INET, IPPROTO_TCP, SOCK_RAW,
};

#[allow(dead_code)]
mod tcp_flag {
    pub const CWR: u8 = 1 << 7;
    pub const ECE: u8 = 1 << 6;
    pub const URG: u8 = 1 << 5;
    pub const ACK: u8 = 1 << 4;
    pub const PSH: u8 = 1 << 3;
    pub const RST: u8 = 1 << 2;
    pub const SYN: u8 = 1 << 1;
    pub const FIN: u8 = 1 << 0;
}

#[allow(dead_code)]
#[derive(Debug)]
struct TcpHeader {
    source_port: u16,
    dest_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
}

#[derive(Debug)]
struct TcpHeaderCreateError<'a> {
    src: &'a [u8],
}

impl std::fmt::Display for TcpHeaderCreateError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP header is malformed: {:?}", self.src)
    }
}
impl std::error::Error for TcpHeaderCreateError<'_> {}

impl TcpHeader {
    fn from_bytes_op(bytes: &[u8]) -> Option<TcpHeader> {
        let mut it = bytes[20..].iter().copied();

        let source_port = u16::from_be_bytes([it.next()?, it.next()?]);
        let dest_port = u16::from_be_bytes([it.next()?, it.next()?]);
        let seq = u32::from_be_bytes([it.next()?, it.next()?, it.next()?, it.next()?]);
        let ack = u32::from_be_bytes([it.next()?, it.next()?, it.next()?, it.next()?]);
        // right 4 bytes are reserved; offset is represented as a number of 32 bit words
        let data_offset = (it.next()? >> 4) * 4;
        let flags = it.next()?;
        let window = u16::from_be_bytes([it.next()?, it.next()?]);
        let checksum = u16::from_be_bytes([it.next()?, it.next()?]);
        let urgent_pointer = u16::from_be_bytes([it.next()?, it.next()?]);

        Some(TcpHeader {
            source_port,
            dest_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            checksum,
            urgent_pointer,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<TcpHeader, TcpHeaderCreateError> {
        match TcpHeader::from_bytes_op(bytes) {
            Some(v) => Ok(v),
            None => Err(TcpHeaderCreateError { src: bytes }),
        }
    }

    fn new_ack(dest_port: u16, source_port: u16) -> TcpHeader {
        TcpHeader {
            source_port,
            dest_port,
            seq: 0,
            ack: 1,
            data_offset: 40,
            flags: tcp_flag::SYN | tcp_flag::ACK,
            window: 0,
            checksum: 0,
            urgent_pointer: 0,
        }
    }

    fn to_bytes(&self) -> [u8; std::mem::size_of::<Self>()] {
        let mut r = [0u8; std::mem::size_of::<Self>()];

        r[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        r[2..4].copy_from_slice(&self.dest_port.to_be_bytes());
        r[4..8].copy_from_slice(&self.seq.to_be_bytes());
        r[8..12].copy_from_slice(&self.ack.to_be_bytes());
        r[12] = self.data_offset;
        r[13] = self.flags;
        r[14..16].copy_from_slice(&self.window.to_be_bytes());
        r[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        r[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());

        r
    }
}

fn main() -> io::Result<()> {
    let sockfd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };

    if sockfd < 0 {
        return Err(io::Error::last_os_error());
    }

    let port: u16 = 8080;
    let addr = Ipv4Addr::new(127, 0, 0, 1);

    let sockaddr_in = sockaddr_in {
        sin_family: AF_INET as u16,
        // unused for raw sockets
        sin_port: 0,
        sin_addr: in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        // padding bytes; unused by kernel
        sin_zero: [0; 8],
    };

    let bind_res = unsafe {
        bind(
            sockfd,
            (&sockaddr_in as *const sockaddr_in).cast::<sockaddr>(),
            mem::size_of::<sockaddr_in>() as u32,
        )
    };

    if bind_res < 0 {
        return Err(io::Error::last_os_error());
    }

    println!("Listening on {}", port);

    let mut buffer = [0u8; 1024];
    let mut src_address: sockaddr_in = unsafe { mem::zeroed() };
    let mut addr_len = mem::size_of::<sockaddr_in>() as u32;

    loop {
        let bytes_received = unsafe {
            recvfrom(
                sockfd,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                0,
                // sockaddr (not _in) is expected here
                (&mut src_address as *mut sockaddr_in).cast(),
                &mut addr_len,
            )
        };

        if bytes_received < 0 {
            return Err(io::Error::last_os_error());
        }

        let header = match TcpHeader::from_bytes(&buffer) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        };

        if header.dest_port != port {
            //println!("Skipping message targeted for {}", header.dest_port);
            continue;
        }

        println!(
            "Received {} bytes from {}: {:?}",
            bytes_received,
            Ipv4Addr::from(u32::from_be(src_address.sin_addr.s_addr)),
            header
        );
        println!("flags {:08b}", header.flags);

        if (header.flags & tcp_flag::SYN) > 0 {
            let ack_header_bytes = TcpHeader::new_ack(header.source_port, port).to_bytes();

            let bytes_sent = unsafe {
                sendto(
                    sockfd,
                    ack_header_bytes.as_ptr() as *const _,
                    ack_header_bytes.len(),
                    0,
                    (&src_address as *const sockaddr_in).cast(),
                    addr_len,
                )
            };

            if bytes_sent < 0 {
                return Err(io::Error::last_os_error());
            }

            println!("Sent {}", bytes_sent);
        }

        if let Some(payload) = &buffer.get(20 + header.data_offset as usize..) {
            println!("Payload: {:?}", &payload);
        } else {
            println!("No payload");
        }
    }
}
