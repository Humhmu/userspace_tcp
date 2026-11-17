use crate::utils;

pub fn handle_icmp(data: &mut [u8]) -> bool {
    if 0 != utils::calculate_checksum(&data) {
        return false;
    }

    data[2] = 0;
    data[3] = 0;

    match data[0] {
        8 => {
            data[0] = 0;
            let checksum = utils::calculate_checksum(&data);
            data[2] = (checksum >> 8) as u8;
            data[3] = (checksum & 0xff) as u8;
            return true;
        },
        _ => {return false},
    }
}
