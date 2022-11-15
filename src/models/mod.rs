use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use regex::Regex;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccountError {
    #[error("malformed input: {0}")]
    Parsing(String),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HmacHash {
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Debug, PartialEq)]
enum OtpType {
    HOTP,
    TOTP,
}

pub struct Account {
    protocol: String,
    otp_type: OtpType,
    label_issuer: String,
    label_account_name: String,
    parameters: Parameters, // queryString
}

pub struct Parameters {
    secret_key: String,
    issuer: String,
    hash_algorithm: HmacHash,
    code_digits: u8,
    counter: i64,
    step_period: u8,
}

impl Account {
    fn decode_label(label: &str) -> Result<(String, String), AccountError> {
        let decoded_s = percent_decode_str(label).decode_utf8_lossy();
        let (issuer, account_name) = match decoded_s.matches(':').count() {
            0 => ("", label),
            1 => decoded_s.split_once(':').unwrap_or(("", label)),
            _ => {
                return Err(AccountError::Parsing(format!(
                    "malformed input: invalid issuer field"
                )))
            }
        };
        Ok((issuer.trim().to_string(), account_name.trim().to_string()))
    }

    pub fn update_secret_key(&mut self, new_key: String) {
        self.parameters.secret_key = new_key;
    }
}

impl fmt::Display for HmacHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_algorithm = match self {
            Self::SHA1 => "SHA1",
            Self::SHA256 => "SHA256",
            Self::SHA512 => "SHA512",
        };
        write!(f, "{}", hash_algorithm)
    }
}

impl fmt::Display for OtpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let otp_type = match self {
            Self::HOTP => "hotp",
            Self::TOTP => "totp",
        };
        write!(f, "{}", otp_type)
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut params = self.parameters.to_string();
        if self.otp_type == OtpType::TOTP {
            let re = Regex::new(r"&counter=[\-]*[0-9]*").unwrap();
            params = re.replace_all(&params, "").to_string();
        } else {
            let re = Regex::new(r"&period=[0-9]*").unwrap();
            params = re.replace_all(&params, "").to_string();
        }

        let encoded_label_issuer =
            utf8_percent_encode(&self.label_issuer, NON_ALPHANUMERIC).to_string();

        write!(
            f,
            "{}://{}/{}:{}?{}",
            self.protocol, self.otp_type, encoded_label_issuer, self.label_account_name, params,
        )
    }
}

impl fmt::Display for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded_issuer = utf8_percent_encode(&self.issuer, NON_ALPHANUMERIC).to_string();
        write!(
            f,
            "secret={}&issuer={}&algorithm={}&digits={}&counter={}&period={}",
            self.secret_key,
            encoded_issuer,
            self.hash_algorithm,
            self.code_digits,
            self.counter,
            self.step_period
        )
    }
}

impl FromStr for Account {
    type Err = AccountError;
    fn from_str(s: &str) -> Result<Self, AccountError> {
        let (uri, query) = s.split_once('?').ok_or(AccountError::Parsing(format!(
            "missing uri parameters:\n{s}"
        )))?;

        let params: Parameters = match Parameters::from_str(query) {
            Ok(x) => x,
            Err(err) => return Err(AccountError::Parsing(format!("{err}:\n{s}"))),
        };

        let (protocol, uri) = uri
            .split_once("://")
            .ok_or(AccountError::Parsing(format!("missing protocol:\n{s}")))?;

        if protocol != "otpauth" {
            return Err(AccountError::Parsing(format!("wrong protocol:\n{s}")));
        }

        let (otp_type, label) = uri.split_once('/').ok_or(AccountError::Parsing(format!(
            "missing otp type or label:\n{s}"
        )))?;

        let otp_type = match otp_type {
            "hotp" => OtpType::HOTP,
            "totp" => OtpType::TOTP,
            _ => return Err(AccountError::Parsing(format!("wrong otp type:\n{s}"))),
        };

        if otp_type == OtpType::HOTP && params.counter == -1 {
            return Err(AccountError::Parsing(format!("missing hotp counter:\n{s}")));
        }

        let (label_issuer, label_account_name) = match Account::decode_label(label) {
            Ok((x, y)) => (x, y),
            Err(err) => return Err(AccountError::Parsing(format!("{err}:\n{s}"))),
        };

        Ok(Account {
            protocol: protocol.to_string(),
            otp_type,
            label_issuer: label_issuer.to_string(),
            label_account_name: label_account_name.to_string(),
            parameters: params,
        })
    }
}

impl FromStr for Parameters {
    type Err = AccountError;
    fn from_str(s: &str) -> Result<Self, AccountError> {
        let params = s.split('&').collect::<Vec<_>>();
        let mut secret_key = "";
        let mut issuer = "";
        let mut hash_algorithm: HmacHash = HmacHash::SHA1;
        let mut code_digits: u8 = 6;
        let mut counter: i64 = -1;
        let mut step_period: u8 = 30;
        for item in params {
            let (key, value) = item.split_once('=').ok_or(AccountError::Parsing(format!(
                "please check the query parameters"
            )))?;
            match key {
                "secret" => secret_key = value,
                "issuer" => issuer = value,
                "algorithm" => {
                    hash_algorithm = match value {
                        "SHA1" => HmacHash::SHA1,
                        "SHA256" => HmacHash::SHA256,
                        "SHA512" => HmacHash::SHA512,
                        _ => HmacHash::SHA1,
                    }
                }
                "digits" => code_digits = value.parse().unwrap_or(6),
                "counter" => counter = value.parse().unwrap_or(-1),
                "period" => step_period = value.parse().unwrap_or(30),
                _ => (),
            }
        }
        if secret_key == "" || issuer == "" {
            return Err(AccountError::Parsing(format!("required fields are empty")));
        }

        let issuer = percent_decode_str(issuer).decode_utf8_lossy();

        Ok(Parameters {
            secret_key: secret_key.to_string(),
            issuer: issuer.to_string(),
            hash_algorithm,
            code_digits,
            counter,
            step_period,
        })
    }
}

#[cfg(test)]
mod tests {
    //TODO: Change panic tests to check specific errors
    use super::*;

    #[test]
    fn parse_uri_all_params() {
        let uri = "otpauth://totp/ACMECo:john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACMECo&algorithm=SHA512&digits=8&period=60";
        let test_account = match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(test_account.otp_type, OtpType::TOTP);
        assert_eq!(test_account.label_issuer, "ACMECo");
        assert_eq!(test_account.label_account_name, "john.doe@email.com");
        assert_eq!(
            test_account.parameters.secret_key,
            "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
        );
        assert_eq!(test_account.parameters.issuer, "ACMECo");
        assert_eq!(test_account.parameters.hash_algorithm, HmacHash::SHA512);
        assert_eq!(test_account.parameters.code_digits, 8);
        assert_eq!(test_account.parameters.step_period, 60);
    }

    #[test]
    #[should_panic]
    fn parse_uri_missing_params() {
        let uri = "otpauth://totp/ACMECo:john.doe@email.com";
        match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
    }

    #[test]
    fn parse_uri_required_params() {
        let uri = "otpauth://totp/ACMECo:john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACMECo";
        let test_account = match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(test_account.otp_type, OtpType::TOTP);
        assert_eq!(test_account.label_issuer, "ACMECo");
        assert_eq!(test_account.label_account_name, "john.doe@email.com");
        assert_eq!(
            test_account.parameters.secret_key,
            "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
        );
        assert_eq!(test_account.parameters.issuer, "ACMECo");
        assert_eq!(test_account.parameters.hash_algorithm, HmacHash::SHA1);
        assert_eq!(test_account.parameters.code_digits, 6);
        assert_eq!(test_account.parameters.step_period, 30);
    }

    #[test]
    fn parse_uri_label_percentage_encoded() {
        let uri = "otpauth://totp/ACME%20Co%3A%20%20%20john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co";
        let test_account = match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(test_account.label_issuer, "ACME Co");
        assert_eq!(test_account.label_account_name, "john.doe@email.com");
        assert_eq!(test_account.parameters.issuer, "ACME Co");
    }

    #[test]
    fn parse_uri_label_issuer_missing() {
        let uri = "otpauth://totp/john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co";
        let test_account = match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(test_account.label_issuer, "");
        assert_eq!(test_account.label_account_name, "john.doe@email.com");
        assert_eq!(test_account.parameters.issuer, "ACME Co");
    }

    #[test]
    #[should_panic]
    fn parse_uri_malformed_otp_type() {
        let uri = "otpauth://xotp/ACMECo:john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACMECo";
        match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
    }

    #[test]
    #[should_panic]
    fn parse_uri_malformed_protocol() {
        let uri = "https://totp/ACMECo:john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACMECo";
        match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
    }

    #[test]
    #[should_panic]
    fn parse_uri_hotp_counter_missing() {
        let uri = "otpauth://hotp/ACMECo:john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACMECo";
        match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
    }

    #[test]
    fn totp_account_to_string() {
        let uri = "otpauth://totp/ACME%20Co%3A%20%20%20john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co";
        let test_account = match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(
            test_account.to_string(),
            "otpauth://totp/ACME%20Co:john.doe@email.com?\
            secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn hotp_account_to_string() {
        let uri = "otpauth://hotp/ACME%20Co%3A%20%20%20john.doe@email.com?\
                   secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&counter=300";
        let test_account = match Account::from_str(uri) {
            Ok(x) => x,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(
            test_account.to_string(),
            "otpauth://hotp/ACME%20Co:john.doe@email.com?\
             secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=300"
        );
    }
}
