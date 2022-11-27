use crate::models::{Account, AccountError};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

pub fn parse_data_file(path: String) -> Result<(String, Vec<Account>), AccountError> {
    let lines = lines_from_file(path);
    let iv = lines.get(1).expect("IV missing from the file");
    let mut account_vec: Vec<Account> = Vec::new();
    for line in lines.iter().skip(2) {
        let account = Account::from_str(line)?;
        account_vec.push(account);
    }
    Ok((iv.to_owned(), account_vec))
}

pub fn parse_plain_file(path: String) -> Result<Vec<Account>, AccountError> {
    let lines = lines_from_file(path);
    let mut account_vec: Vec<Account> = Vec::new();
    for line in lines.iter() {
        let account = Account::from_str(line)?;
        account_vec.push(account);
    }
    Ok(account_vec)
}

fn lines_from_file<P>(filename: P) -> Vec<String>
where
    P: AsRef<Path>,
{
    let file = File::open(filename).expect("invalid file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Couldn't parse line"))
        .collect()
}
