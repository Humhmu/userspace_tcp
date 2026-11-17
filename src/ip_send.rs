use std::io::Write;
use crate::ipv4;
use crate::utils;

pub fn send_packet(dev: &mut tun::Device, header: &mut ipv4::Ipv4Header, data: &[u8]) {
    let mut header_bytes = vec![0u8; header.header_len];
    header.get_bytes(&mut header_bytes);
    header.header_checksum = utils::calculate_checksum(&header_bytes);
    header.get_bytes(&mut header_bytes);

    let mut packet = Vec::with_capacity(header_bytes.len() + data.len());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(data);

    let _ = dev.write(&packet);
}
