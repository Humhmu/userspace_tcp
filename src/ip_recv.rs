use crate::ipv4;
use crate::tcp;

pub fn handle_packet(dev: &mut tun::Device, tcbs: &mut Vec<tcp::TCB>, buf: &mut [u8; 1504], n: usize) {
    let version: u8 = buf[0] >> 4;
    match version {
        4 => {
            println!("Handling IPv4 packet.");
            ipv4::handle_ipv4(dev, tcbs, buf, n);
        },
        v => println!("Version {v} not supported."),
    }
}
