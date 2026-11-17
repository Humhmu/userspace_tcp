pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut checksum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        checksum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        checksum += (*last as u32) << 8; // pad on the right with a zero byte
    }
    while (checksum >> 16) != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    !(checksum as u16)
}
