use std::{io, mem, net::Ipv4Addr};

use libc::{
    bind, in_addr, recvfrom, sendto, sockaddr, sockaddr_in, socket, AF_INET, IPPROTO_TCP, SOCK_RAW,
};

#[derive(Debug)]
enum IpHeaderError {
    InvalidLen { required_len: usize, len: usize },
    InvalidVersion { value: usize },
    HeaderLengthIsSmallerThanHeader { value: usize },
}

impl std::fmt::Display for IpHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpHeaderError::InvalidLen { required_len, len } => write!(
                f,
                "Invalid header length: required {}, got {}",
                required_len, len
            ),
            IpHeaderError::InvalidVersion { value } => {
                write!(f, "Invalid IP version {} ({:08b})", value, value)
            }
            IpHeaderError::HeaderLengthIsSmallerThanHeader { value } => {
                write!(
                    f,
                    "Header length is smaller than the header itself, {}",
                    value
                )
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct IpHeader {
    // version's always equal to 4; ihl >= 5
    version_ihl: u8,
    dscp_ecn: u8,
    total_len: u16,
    identication: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
}

impl IpHeader {
    const MIN_LEN: usize = std::mem::size_of::<IpHeader>();

    fn from_bytes(bytes: &[u8]) -> Result<IpHeader, IpHeaderError> {
        if bytes.len() < IpHeader::MIN_LEN {
            return Err(IpHeaderError::InvalidLen {
                required_len: IpHeader::MIN_LEN,
                len: bytes.len(),
            });
        }

        let version = bytes[0] >> 4;
        if version != 4 {
            return Err(IpHeaderError::InvalidVersion {
                value: version as usize,
            });
        }

        let ihl = bytes[0] & 0x0F;
        if ihl < 5 {
            return Err(IpHeaderError::HeaderLengthIsSmallerThanHeader {
                value: ihl as usize,
            });
        }

        Ok(IpHeader {
            version_ihl: bytes[0],
            dscp_ecn: bytes[1],
            total_len: u16::from_be_bytes([bytes[2], bytes[3]]),
            identication: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_fragment_offset: u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl: bytes[8],
            protocol: bytes[9],
            header_checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            source_addr: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            dest_addr: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        })
    }

    fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    fn get_tcp_header_bytes<'a>(&self, tcp_header_slice: &'a [u8]) -> &'a [u8] {
        &tcp_header_slice[std::mem::size_of::<IpHeader>() + (self.ihl() as usize - 5)..]
    }
}

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
struct TcpHeaderParseError<'a> {
    src: &'a [u8],
}

impl std::fmt::Display for TcpHeaderParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP header is malformed: {:?}", self.src)
    }
}
impl std::error::Error for TcpHeaderParseError<'_> {}

impl TcpHeader {
    fn from_bytes_op(bytes: &[u8]) -> Option<TcpHeader> {
        let mut it = bytes.iter().copied();

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

    fn from_bytes(bytes: &[u8]) -> Result<TcpHeader, TcpHeaderParseError> {
        match TcpHeader::from_bytes_op(bytes) {
            Some(v) => Ok(v),
            None => Err(TcpHeaderParseError { src: bytes }),
        }
    }

    fn get_pseudo_header_bytes(&self, dest_ip: u16, src_ip: u16, ip_header_len: &usize) -> [u8; 8] {
        let mut r = [0u8; 8];

        r[0..2].copy_from_slice(&dest_ip.to_be_bytes());
        r[2..4].copy_from_slice(&src_ip.to_be_bytes());
        r[4] = 0;
        r[5] = IPPROTO_TCP as u8;
        r[6..8].copy_from_slice(&(&self.to_bytes().len() + ip_header_len).to_be_bytes());

        r
    }

    //fn get_checksum(&self) -> u16 {}

    fn new_ack(dest_port: u16, source_port: u16, syn: u32) -> TcpHeader {
        TcpHeader {
            source_port,
            dest_port,
            seq: 123,
            ack: syn + 1,
            data_offset: ((std::mem::size_of::<TcpHeader>() / 4) << 4) as u8,
            flags: tcp_flag::ACK | tcp_flag::SYN,
            // this one should be calculated based on bandwidth, but I don't care
            window: 65495,
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

    let mut recv_buffer = [0u8; 1024];
    let mut src_address: sockaddr_in = unsafe { mem::zeroed() };
    let mut addr_len = mem::size_of::<sockaddr_in>() as u32;

    loop {
        let bytes_received = unsafe {
            recvfrom(
                sockfd,
                recv_buffer.as_mut_ptr() as *mut _,
                recv_buffer.len(),
                0,
                // sockaddr (not _in) is expected here
                (&mut src_address as *mut sockaddr_in).cast(),
                &mut addr_len,
            )
        };

        if bytes_received < 0 {
            return Err(io::Error::last_os_error());
        }

        let ip_header = match IpHeader::from_bytes(&recv_buffer) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        };

        let tcp_header = match TcpHeader::from_bytes(ip_header.get_tcp_header_bytes(&recv_buffer)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        };

        if tcp_header.dest_port != port {
            continue;
        }

        println!(
            "Received {} bytes from {}",
            bytes_received,
            Ipv4Addr::from(u32::from_be(src_address.sin_addr.s_addr)),
        );
        println!("{:?}", ip_header);
        println!("{:?}", tcp_header);
        println!("tcp flags {:08b}", tcp_header.flags);

        if (tcp_header.flags & tcp_flag::SYN) > 0 {
            let ack_header = TcpHeader::new_ack(tcp_header.source_port, port, tcp_header.seq);
            let ack_header_bytes = ack_header.to_bytes();
            println!("{:?}", ack_header);

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

        println!(
            "Payload: {:?}",
            &recv_buffer[tcp_header.data_offset as usize..(bytes_received as usize)]
        );
    }
}
