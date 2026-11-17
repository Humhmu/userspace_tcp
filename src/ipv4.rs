use crate::icmpv4;
use crate::ip_send;
use crate::tcp;
use crate::utils;

pub struct Ipv4Header {
    version: u8, // dont know if theres a better way to store words of data < 8bits
    ihl: u8,
    pub header_len: usize,
    differentiated_services: u8,
    total_len: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_addr: u32,
    pub dest_addr: u32,
    options: Vec<u8>, // vector as size of options is variable
}

impl Ipv4Header {
    pub fn parse_header(packet: &mut [u8], n: usize) -> Option<Self> {
        let ihl = packet[0] & 0x0f;
        let header_len = (ihl as usize) * 4;
        let total_len = u16::from_be_bytes([packet[2], packet[3]]);

        if
            ihl < 5 ||
            (total_len as usize) != n ||
            0 != utils::calculate_checksum(&packet[..header_len]) {
                return None;
        }

        Some(Self {
            version: packet[0] >> 4,
            ihl,
            header_len,
            differentiated_services: packet[1],
            total_len,
            identification: u16::from_be_bytes([packet[4], packet[5]]),
            flags: packet[6] >> 5,
            fragment_offset: u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff,
            ttl: packet[8],
            protocol: packet[9],
            header_checksum: u16::from_be_bytes([packet[10], packet[11]]),
            source_addr: u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]),
            dest_addr: u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]),
            options: packet[20..header_len].to_vec(),
        })
    }

    pub fn get_bytes(&mut self, buf: &mut [u8]) {
        buf[0] = self.version << 4 | self.ihl;
        buf[1] = self.differentiated_services;
        buf[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        buf[6..8].copy_from_slice(&((self.flags as u16) << 13 | self.fragment_offset).to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&self.header_checksum.to_be_bytes());
        buf[12..16].copy_from_slice(&self.source_addr.to_be_bytes());
        buf[16..20].copy_from_slice(&self.dest_addr.to_be_bytes());
        buf[20..].copy_from_slice(&self.options);
    }
}

pub fn handle_ipv4(dev: &mut tun::Device, tcbs: &mut Vec<tcp::TCB>, buf: &mut [u8; 1504], n: usize) {
    let mut header = Ipv4Header::parse_header(buf, n).unwrap();
    let data = &mut buf[header.header_len..n];

    // TODO handle options

    match header.protocol {
        1 => {
            println!("  Handling ICMPv4 packet.");
            match icmpv4::handle_icmp(data) {
                true => {
                    (header.source_addr, header.dest_addr) = (header.dest_addr, header.source_addr);
                    header.header_checksum = 0;
                    ip_send::send_packet(dev, &mut header, &data);
                },
                false => return,
            };
        }
        6 => {
            println!("  Handling TCP packet.");
            tcp::handle_tcp(dev, tcbs, &mut header, data);
        },
        p => println!("  Protocol {p} not supported."),
    }
}
