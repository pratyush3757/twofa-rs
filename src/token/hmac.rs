use crate::models::HmacHash;
use hex;
use ring::hmac;

pub fn create_token() -> String {
    let key_value: &[u8; 20] = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
                                 \x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
                                 \x0b\x0b\x0b\x0b";
    let msg = hex::decode("4869205468657265").expect("00");
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key_value.as_ref());
    let tag = hmac::sign(&hmac_key, &msg.as_ref());

    hex::encode(tag.as_ref())
}

pub fn compute_hmac(
    hex_encoded_key: &str,
    hex_encoded_message: &str,
    hash_algorithm: HmacHash,
) -> String {
    let hmac_key = match hex::decode(hex_encoded_key) {
        Ok(x) => x,
        Err(_) => vec![0],
    };
    let algo = match hash_algorithm {
        HmacHash::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HmacHash::SHA256 => hmac::HMAC_SHA256,
        HmacHash::SHA512 => hmac::HMAC_SHA512,
    };
    let msg = match hex::decode(hex_encoded_message) {
        Ok(x) => x,
        Err(_) => vec![0],
    };
    let hmac_key = hmac::Key::new(algo, hmac_key.as_ref());
    let tag = hmac::sign(&hmac_key, &msg.as_ref());

    hex::encode(tag.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_case_1_key_matching_output_length() {
        // Test with the key length equal to output length.
        // Originally defined (in RFC 2202) only for SHA-1,
        // extended to other digests in RFC 4231
        let hex_encoded_key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"; // 20 bytes
        let hex_encoded_message = "4869205468657265"; // "Hi There" 8 bytes

        assert_eq!(
            "b617318655057264e28bc0b6fb378c8ef146be00",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
        );
        assert_eq!(
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
        );
        assert_eq!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb0\
             2379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4\
             be9d914eeb61f1702e696c203a126854",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
        );
    }

    #[test]
    fn rfc_case_2_key_smaller_than_output_length() {
        // Test with a key shorter than the length of the HMAC output.
        let hex_encoded_key = "4a656665"; // "Jefe" 4 bytes
        let hex_encoded_message = "7768617420646f2079612077616e7420\
                                   666f72206e6f7468696e673f";
        // "what do ya want for nothing?"
        // 28 bytes

        assert_eq!(
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
        );
        assert_eq!(
            "5bdcc146bf60754e6a042426089575c7\
             5a003f089d2739839dec58b964ec3843",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
        );
        assert_eq!(
            "164b7a7bfcf819e2e395fbe73b56e0a3\
             87bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fd\
             caeab1a34d4a6b4b636e070a38bce737",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
        );
    }

    #[test]
    fn rfc_case_3_input_longer_than_output_length() {
        // Test with a combined length of key and data that is larger than 64
        // bytes (= block-size of SHA-224 and SHA-256).
        // Key equal length with output
        let hex_encoded_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaa"; // 20 bytes
        let hex_encoded_message = "dddddddddddddddddddddddddddddddd\
                                   dddddddddddddddddddddddddddddddd\
                                   dddddddddddddddddddddddddddddddd\
                                   dddd"; // 50 bytes

        assert_eq!(
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
        );
        assert_eq!(
            "773ea91e36800e46854db8ebd09181a7\
             2959098b3ef8c122d9635514ced565fe",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
        );
        assert_eq!(
            "fa73b0089d56a284efb0f0756c890be9\
             b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807\
             b946a337bee8942674278859e13292fb",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
        );
    }

    #[test]
    fn rfc_case_4_input_longer_than_output_length_2() {
        // Test with a combined length of key and data that is larger than 64
        // bytes (= block-size of SHA-224 and SHA-256).
        // Key longer than output
        let hex_encoded_key = "0102030405060708090a0b0c0d0e0f10\
                               111213141516171819"; // 25 bytes
        let hex_encoded_message = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                                   cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                                   cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                                   cdcd"; // 50 bytes

        assert_eq!(
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
        );
        assert_eq!(
            "82558a389a443c0ea4cc819899f2083a\
             85f0faa3e578f8077a2e3ff46729665b",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
        );
        assert_eq!(
            "b0ba465637458c6990e5a8c5f61d4af7\
             e576d97ff94b872de76f8050361ee3db\
             a91ca5c11aa25eb4d679275cc5788063\
             a5f19741120c4f2de2adebeb10a298dd",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
        );
    }

    #[test]
    fn rfc_case_5_truncation_of_output() {
        // Test with a truncation of output to 128 bits.
        // Digest-96 in case of SHA1
        let hex_encoded_key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c\
                               0c0c0c0c"; // 20 bytes
        let hex_encoded_message = "546573742057697468205472756e6361\
                                   74696f6e"; // "Test With Truncation" 20 bytes

        assert_eq!(
            "4c1a03424b55e07fe7f27be1",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
                .chars()
                .take(24)
                .collect::<String>() // Truncated to Digest-96 as per RFC 2202
        );
        assert_eq!(
            "a3b6167473100ee06e0c796c2955552b",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
                .chars()
                .take(32)
                .collect::<String>() // Truncated to 128 bits as per RFC 4231
        );
        assert_eq!(
            "415fad6271580a531d4179bc891d87a6",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
                .chars()
                .take(32)
                .collect::<String>() // Truncated to 128 bits as per RFC 4231
        );
    }

    #[test]
    fn rfc_case_6_key_longer_than_block() {
        // Test with key larger than block size
        let hex_encoded_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 80 bytes
        let hex_encoded_message = "54657374205573696e67204c61726765\
                                   72205468616e20426c6f636b2d53697a\
                                   65204b6579202d2048617368204b6579\
                                   204669727374";
        // "Test Using Larger Than Block-Size Key - Hash Key First"
        // 54 bytes

        assert_eq!(
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
        );

        let hex_encoded_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaa";
        // 131 bytes (> 128 bytes =  block-size of SHA-384 and SHA-512)

        assert_eq!(
            "60e431591ee0b67f0d8a26aacbf5b77f\
             8e0bc6213728c5140546040f0ee37f54",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
        );
        assert_eq!(
            "80b24263c7c1a3ebb71493c1dd7be8b4\
             9b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e52\
             95e64f73f63f0aec8b915a985d786598",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
        );
    }

    #[test]
    fn rfc_case_7_input_longer_than_block() {
        // Test with a key and data that is larger than block size
        let hex_encoded_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 80 bytes
        let hex_encoded_message = "54657374205573696e67204c61726765\
                                   72205468616e20426c6f636b2d53697a\
                                   65204b657920616e64204c6172676572\
                                   205468616e204f6e6520426c6f636b2d\
                                   53697a652044617461";
        // "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        // 73 bytes

        assert_eq!(
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA1)
        );

        let hex_encoded_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                               aaaaaa";
        // 131 bytes (> 128 bytes =  block-size of SHA-384 and SHA-512)
        let hex_encoded_message = "54686973206973206120746573742075\
                                   73696e672061206c6172676572207468\
                                   616e20626c6f636b2d73697a65206b65\
                                   7920616e642061206c61726765722074\
                                   68616e20626c6f636b2d73697a652064\
                                   6174612e20546865206b6579206e6565\
                                   647320746f2062652068617368656420\
                                   6265666f7265206265696e6720757365\
                                   642062792074686520484d414320616c\
                                   676f726974686d2e";
        // "This is a test using a larger than block-size key and a larger than block-size data. "
        // "The key needs to be hashed before being used by the HMAC algorithm."
        // 152 bytes (> 128 bytes =  block-size of SHA-384 and SHA-512)

        assert_eq!(
            "9b09ffa71b942fcb27635fbcd5b0e944\
             bfdc63644f0713938a7f51535c3a35e2",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA256)
        );
        assert_eq!(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffd\
             debd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15\
             134676fb6de0446065c97440fa8c6a58",
            compute_hmac(hex_encoded_key, hex_encoded_message, HmacHash::SHA512)
        );
    }
}
