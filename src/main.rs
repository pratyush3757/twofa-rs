mod fsio;
mod models;
mod token;
use models::{Account, HmacHash};
use std::str::FromStr;

fn main() {
    let hmac_token = token::hmac::create_token();
    assert_eq!(
        hmac_token, "b617318655057264e28bc0b6fb378c8ef146be00",
        "Values are not equal"
    );

    let hmac_secret_key = "4a656665"; //Jefe
    let hex_encoded_message = "7768617420646f2079612077616e7420\
                               666f72206e6f7468696e673f"; /*what do ya want for nothing?*/

    let sha1 = token::hmac::compute_hmac(hmac_secret_key, hex_encoded_message, HmacHash::SHA1);
    println!("{}", sha1);

    let sha256 = token::hmac::compute_hmac(hmac_secret_key, hex_encoded_message, HmacHash::SHA256);
    println!("{}", sha256);

    let sha512 = token::hmac::compute_hmac(hmac_secret_key, hex_encoded_message, HmacHash::SHA512);
    println!("{}", sha512);

    let hotp_secret_key = "12345678901234567890";
    let code_digits = 6;
    for counter in 0..10i64 {
        let sha1 = token::otp::compute_hotp(hotp_secret_key, counter, code_digits, HmacHash::SHA1);
        println!("{}", sha1);
    }

    let ascii_key = "12345678901234567890";
    let hex_key = hex::encode(ascii_key);
    let code_digits = 8;
    let hash_algorithm = HmacHash::SHA1;
    let period = 30;
    let time_otp_list = [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ];
    for item in time_otp_list.into_iter() {
        assert_eq!(
            item.1,
            token::otp::compute_totp(&hex_key, item.0, code_digits, hash_algorithm, period)
        );
    }
    println!("Matched all totp cases");

    let uri = "otpauth://totp/ACME%20Co%3A%20%20%20john.doe@email.com?\
               secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60";
    let hotp_uri = "otpauth://hotp/ACMECo:john.doe@email.com?\
                    secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACMECo&algorithm=SHA256&digits=8&counter=300";
    let mut acc1 = Account::from_str(uri).unwrap();
    let acc2 = Account::from_str(hotp_uri).unwrap();
    println!("{acc1}\n{acc2}");
    acc1.update_secret_key("AAGAYEMERIMAUTKATAMASHADEKHNE".to_string());
    println!("{acc1}");
}
