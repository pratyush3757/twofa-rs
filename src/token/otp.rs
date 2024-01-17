use crate::models::HmacHash;
use crate::token::hmac;
use byteorder::{BigEndian, ByteOrder};

pub fn compute_otp_lifetime(time: i64, step_period: u8) -> u8 {
    step_period - (time % i64::from(step_period)) as u8
}

pub fn compute_totp(
    key: &str,
    time: i64,
    digits: u8,
    hash_algorithm: HmacHash,
    step_period: u8,
) -> String {
    let timestep = time / i64::from(step_period);

    compute_hotp(key, timestep, digits, hash_algorithm)
}

pub fn compute_hotp(key: &str, counter: i64, digits: u8, hash_algorithm: HmacHash) -> String {
    // See HTOP errata https://www.rfc-editor.org/errata/eid6702
    // Counter value is considered big endian, key is little endian
    let mut unpacked_counter = [0; 8];
    BigEndian::write_i64(&mut unpacked_counter, counter);

    let hex_encoded_counter: String = hex::encode(unpacked_counter);
    let hex_encoded_mac: String = hmac::compute_hmac(key, &hex_encoded_counter, hash_algorithm);
    let mac: Vec<u8> = match hex::decode(hex_encoded_mac) {
        Ok(x) => x,
        Err(_) => vec![0],
    };
    let offset: usize = match mac.last() {
        Some(x) => (*x & 0xf).into(),
        None => 0,
    };
    let truncated_decimal_otp = {
        (u32::from(mac[offset] & 0x7f) << 24)
            | (u32::from(mac[offset + 1]) << 16)
            | (u32::from(mac[offset + 2]) << 8)
            | u32::from(mac[offset + 3])
    };
    let hotp = truncated_decimal_otp % u32::pow(10, digits.into());

    format!("{:0>width$}", hotp.to_string(), width = usize::from(digits))
}

#[cfg(test)]
mod tests {
    use super::*;

    static TOTP_TIME_LIST: [i64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];

    #[test]
    fn rfc_hotp_sha1() {
        let ascii_key = "12345678901234567890";
        let hex_key = hex::encode(ascii_key);
        let code_digits = 6;
        let hash_algorithm = HmacHash::SHA1;
        let expected_otp_list = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, otp) in expected_otp_list.into_iter().enumerate() {
            let counter_num: i64 = counter.try_into().unwrap();
            assert_eq!(
                otp,
                compute_hotp(&hex_key, counter_num, code_digits, hash_algorithm)
            );
        }
    }

    #[test]
    fn rfc_totp_sha1() {
        let ascii_key = "12345678901234567890";
        let hex_key = hex::encode(ascii_key);
        let code_digits = 8;
        let hash_algorithm = HmacHash::SHA1;
        let step_period = 30;
        let expected_otp_list = [
            "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
        ];
        for (time, otp) in TOTP_TIME_LIST
            .into_iter()
            .zip(expected_otp_list.into_iter())
        {
            assert_eq!(
                otp,
                compute_totp(&hex_key, time, code_digits, hash_algorithm, step_period)
            );
        }
    }

    #[test]
    fn rfc_totp_sha256() {
        let ascii_key = "12345678901234567890\
                         123456789012";
        let hex_key = hex::encode(ascii_key);
        let code_digits = 8;
        let hash_algorithm = HmacHash::SHA256;
        let step_period = 30;
        let expected_otp_list = [
            "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
        ];
        for (time, otp) in TOTP_TIME_LIST
            .into_iter()
            .zip(expected_otp_list.into_iter())
        {
            assert_eq!(
                otp,
                compute_totp(&hex_key, time, code_digits, hash_algorithm, step_period)
            );
        }
    }

    #[test]
    fn rfc_totp_sha512() {
        let ascii_key = "12345678901234567890\
                         12345678901234567890\
                         12345678901234567890\
                         1234";
        let hex_key = hex::encode(ascii_key);
        let code_digits = 8;
        let hash_algorithm = HmacHash::SHA512;
        let step_period = 30;
        let expected_otp_list = [
            "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
        ];
        for (time, otp) in TOTP_TIME_LIST
            .into_iter()
            .zip(expected_otp_list.into_iter())
        {
            assert_eq!(
                otp,
                compute_totp(&hex_key, time, code_digits, hash_algorithm, step_period)
            );
        }
    }
}
