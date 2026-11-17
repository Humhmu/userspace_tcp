use crate::ipv4;
use crate::utils;
use crate::ip_send;

#[derive(Clone, Copy, Debug)]
enum States {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug)]
enum Events {
    Open,
    Snd,
    Receive,
    Close,
    Abort,
    Status,
    SegmentArrives,
    UserTimeout,
    RetransmissionTimeout,
    TimeWaitTimeout,
}

impl States {
    fn next(&self, event: Events, tcb: &mut TCB, flags: &mut Flags, tcp_header: &mut TCPHeader, ipv4_header: &mut ipv4::Ipv4Header, data: &[u8], dev: &mut tun::Device) -> Self {
        use self::States::*;
        use self::Events::*;

        match (self, event) { // Writing out all behaviours from rfc, will not all be
                              // implemented (at least at once)
            // (Closed, Open) => {},
            // (Listen, Open) => {},
            // (_, Open) => {},
            //
            // (Closed, Snd) => {},
            // (Listen, Snd) => {},
            // (SynReceived | SynSent, Snd) => {
            //     *self
            // },
            // (CloseWait | Established, Snd) => {
            //     *self
            // },
            // (_, Snd) => {},
            //
            // (Closed, Receive) => {},
            // (SynReceived | SynSent | Listen, Receive) => {
            //     *self
            // },
            // (FinWait2 | FinWait1 | Established, Receive) => {
            //     *self
            // },
            // (CloseWait, Receive) => {},
            // (_, Receive) => {},
            //
            // (Closed, Close) => {},
            // (Listen, Close) => {
            //     Closed
            // },
            // (SynSent, Close) => {
            //     *self
            // },
            // (SynReceived, Close) => {
            //     FinWait1
            // },
            // (Established, Close) => {
            //     FinWait1
            // },
            // (FinWait2 | FinWait1, Close) => {},
            // (CloseWait, Close) => {},
            // (_, Close) => {},
            //
            // (Closed, Abort) => {},
            // (Listen, Abort) => {},
            // (SynSent, Abort) => {},
            // (TimeWait | LastAck | Closing, Abort) => {},
            // (_, Abort) => {}
            //
            // (Closed, SegmentArrives) => {},
            (Listen, SegmentArrives) => segment_arrives_listen(tcb, flags, tcp_header, ipv4_header, data, dev),
            // (SynSent, SegmentArrives) => {},
            // (_, SegmentArrives) => {},
            //
            // (_, Status) => {},
            // (_, UserTimeout) => {},
            // (_,             RetransmissionTimeout)  => {},
            // (_,             TimeWaitTimeout)        => {},
            (s, e) => {
                println!("Invalid State/Event combination: {:?} {:?}", s, e);
                States::Closed
            },
        }
    }

}

pub struct TCB {
    source_addr: u32,
    dest_addr: u32,
    source_port: u16,
    dest_port: u16,
    state: States,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u16,
    snd_wl1: u32,
    snd_wl2: u32,
    iss: u32,
    rcv_nxt: u32,
    rcv_wnd: u16,
    irs: u32,
}

impl TCB {
    fn new(source_addr: u32, dest_addr: u32, source_port: u16, dest_port: u16
        , ) -> TCB {
        TCB {
            source_addr,
            dest_addr,
            source_port,
            dest_port,
            state: States::Listen,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            irs: 0,
        }
    }
}

#[derive(Copy, Clone)]
struct Flags {
    ae: bool,
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl Flags {
    const AE: u16 = 1<<8;
    const CWR: u16 = 1<<7;
    const ECE: u16 = 1<<6;
    const URG: u16 = 1<<5;
    const ACK: u16 = 1<<4;
    const PSH: u16 = 1<<3;
    const RST: u16 = 1<<2;
    const SYN: u16 = 1<<1;
    const FIN: u16 = 1;

    fn parse_ctl_bits(bits: u16) -> Self {
        Self {
            ae: bits & Self::AE != 0,
            cwr: bits & Self::CWR != 0,
            ece: bits & Self::ECE != 0,
            urg: bits & Self::URG != 0,
            ack: bits & Self::ACK != 0,
            psh: bits & Self::PSH != 0,
            rst: bits & Self::RST != 0,
            syn: bits & Self::SYN != 0,
            fin: bits & Self::FIN != 0,
        }
    }

    fn get_bytes(self) -> u16 {
        (self.ae as u16) << 8
            | (self.cwr as u16) << 7
            | (self.ece as u16) << 6
            | (self.urg as u16) << 5
            | (self.ack as u16) << 4
            | (self.psh as u16) << 3
            | (self.rst as u16) << 2
            | (self.syn as u16) << 1
            | (self.fin as u16)
    }

    fn set_false(&mut self) {
        self.ae = false;
        self.cwr = false;
        self.ece = false;
        self.urg = false;
        self.ack = false;
        self.psh = false;
        self.rst = false;
        self.syn = false;
        self.fin = false;
    } 
}

struct TCPHeader {
    source_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u8,
    header_len: usize,
    control_bits: u16,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: Vec<u8>,
}

impl TCPHeader {
    pub fn parse_header(data: &mut [u8]) -> Option<Self> {
        let data_offset = data[12] >> 4;
        let header_len = (data_offset as usize) * 4;

        Some(Self {
            source_port: u16::from_be_bytes([data[0], data[1]]),
            dest_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset,
            header_len,
            control_bits: u16::from_be_bytes([data[12], data[13]]) & 0x0fff,
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
            options: data[20..header_len].to_vec(),
        })
    }

    pub fn get_bytes(&mut self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dest_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        buf[12..14].copy_from_slice(&((self.data_offset as u16) << 12 | self.control_bits).to_be_bytes()); 
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        buf[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        buf[20..].copy_from_slice(&self.options);
    }

}

pub fn handle_tcp(dev: &mut tun::Device, tcbs: &mut Vec<TCB>, ipv4_header: &mut ipv4::Ipv4Header, data: &mut [u8]) {
    let mut tcp_header = TCPHeader::parse_header(data).unwrap();
    let tcp_data = &mut data[tcp_header.header_len..];

    if tcp_checksum(ipv4_header, &mut tcp_header, tcp_data) != 0 {
        return;
    }

    let tcb = tcbs.iter_mut().find(|tcb| 
        tcb.source_addr == ipv4_header.source_addr &&
        tcb.source_port == tcp_header.source_port &&
        tcb.dest_addr == ipv4_header.dest_addr &&
        tcb.dest_port == tcp_header.dest_port);

    let tcb = match tcb {
        Some(tcb) => {
            println!("TCB Found");
            tcb
        },
        None => {
            tcbs.push(TCB::new(ipv4_header.source_addr,
                    ipv4_header.dest_addr,
                    tcp_header.source_port,
                    tcp_header.dest_port,
            ));
            println!("TCB Created");
            tcbs.last_mut().unwrap()
        },
    };

    let mut flags = Flags::parse_ctl_bits(tcp_header.control_bits);

    let state = tcb.state;
    println!("{0}", flags.syn);
    tcb.state = state.next(Events::SegmentArrives, tcb, &mut flags, &mut tcp_header, ipv4_header, &tcp_data, dev);

}

fn segment_arrives_listen(tcb: &mut TCB, flags: &mut Flags, tcp_header: &mut TCPHeader, ipv4_header: &mut ipv4::Ipv4Header, tcp_data: &[u8], dev: &mut tun::Device) -> States {
    if flags.rst { return States::Listen; };
    if flags.ack {
        // send reset
        return States::Listen;
    }

    if flags.syn {
        // TODO check security?
        tcb.rcv_nxt = tcp_header.seq_num+1;
        tcb.irs = tcp_header.seq_num;
        tcb.iss = 0; // temporary: TODO check how iss should actually be set
        // TODO queue any other control or text for processing in SynReceived state
        flags.set_false();
        flags.syn = true;
        flags.ack = true;
        send_tcp(dev, ipv4_header, tcp_header, tcb.iss, tcb.rcv_nxt, flags);
        tcb.snd_nxt = tcb.iss+1;
        tcb.snd_una = tcb.iss;
        return States::SynReceived;
    } else {
        return States::Listen;
    }
}

fn tcp_checksum(ipv4_header: &mut ipv4::Ipv4Header, tcp_header: &mut TCPHeader, data: &mut [u8]) -> u16 {
    let mut psuedo_header = [0u8; 12];
    psuedo_header[0..4].copy_from_slice(&ipv4_header.source_addr.to_be_bytes());
    psuedo_header[4..8].copy_from_slice(&ipv4_header.dest_addr.to_be_bytes());
    psuedo_header[8] = 0;
    psuedo_header[9] = ipv4_header.protocol;
    psuedo_header[10..12].copy_from_slice(&(((tcp_header.header_len + data.len()) as u16).to_be_bytes()));

    let mut tcp_header_bytes = vec![0u8; tcp_header.header_len];
    tcp_header.get_bytes(&mut tcp_header_bytes);

    let mut checksum_data = vec![0u8; psuedo_header.len() + data.len() + tcp_header_bytes.len()];
    checksum_data.extend_from_slice(&psuedo_header);
    checksum_data.extend_from_slice(&tcp_header_bytes);
    checksum_data.extend_from_slice(&data);
    utils::calculate_checksum(&checksum_data)
}

fn send_tcp(dev: &mut tun::Device, ipv4_header: &mut ipv4::Ipv4Header, tcp_header: &mut TCPHeader, seq: u32, ack: u32, flags: &mut Flags) {
    tcp_header.seq_num = seq;
    tcp_header.ack_num = ack;
    (tcp_header.source_port, tcp_header.dest_port) = (tcp_header.dest_port, tcp_header.source_port);
    let flag_bytes = flags.get_bytes();
    tcp_header.control_bits = flag_bytes;
    tcp_header.checksum = 0;
    tcp_header.checksum = tcp_checksum(ipv4_header, tcp_header, &mut [0u8; 0]);
    (ipv4_header.source_addr, ipv4_header.dest_addr) = (ipv4_header.dest_addr, ipv4_header.source_addr);
    ipv4_header.header_checksum = 0;
    let mut tcp_bytes = vec![0u8; tcp_header.header_len];
    tcp_header.get_bytes(&mut tcp_bytes);
    ip_send::send_packet(dev, ipv4_header, &tcp_bytes)
}

