mod args;
use args::parse_args;
use std::io::{self, Write};
use std::process;
use std::vec;
mod ciphers;
mod key_deriv;
mod ope;
use rpassword::read_password;
use std::fs::File;
use std::io::Result;
use zeroize::Zeroizing;
// fn write_file(file_path: &str, contents: &str) -> Result<()> {
//     let mut file = File::create(file_path)?;
//     file.write_all(contents.as_bytes())
// }
fn write_fileb(file_path: &str, contents: &[u8]) -> Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(contents)
}
fn main() {
    let (input, output, d, e, sigs_check) = parse_args();
    print!("enter pharsepass: ");
    io::stdout().flush().unwrap();
    let mut pharsepass = read_password().expect("eror while reading password");
    let mut res: Vec<u8> = vec![0u8, 1u8];
    if e {
        res = ope::operations::encrypt(input, &Zeroizing::new(std::mem::take(&mut pharsepass)));
    } else if d {
        res = ope::operations::decrypt(
            input,
            sigs_check,
            &Zeroizing::new(std::mem::take(&mut pharsepass)),
        );
    }
    let out_path = if e { format!("{output}.ary") } else { output };
    let _ = write_fileb(&out_path, &res);
}
