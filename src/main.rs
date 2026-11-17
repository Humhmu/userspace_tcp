use std::io::Read;
mod ip_recv;
mod ip_send;
mod ipv4;
mod icmpv4;
mod tcp;
mod utils;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = tun::Configuration::default();
    config
        .tun_name("tun_tcp")
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun::create(&config)?;
    let mut buf = [0u8; 1504];
    let mut tcbs: Vec<tcp::TCB> = Vec::new();
    
    loop {
        let n: usize = dev.read(&mut buf)?;
        ip_recv::handle_packet(&mut dev, &mut tcbs, &mut buf, n);
    }
}


