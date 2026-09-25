use ml_dsa::{MlDsa87, Signature, SignatureEncoding, SigningKey};
use rpassword::read_password;
use slh_dsa::SlhDsaKeyPair;
use std::io::{self, Write};
mod args;
mod ciphers;
use ciphers::*;
mod key_deriv;
use crate::{
    args::parse_args,
    ciphers::{
        aes256::{aes_decrypt, aes_encrypt},
        ascon128::{ascon_decrypt, ascon_encrypt},
        camellia::{camellia_decrypt, camellia_encrypt},
        mldsa::{mldsa_generatekey, mldsa_sign, mldsa_verify},
        twofish256,
        xchacha20::{xchacha20_decrypt, xchacha20_encrypt},
    },
};
use base64::prelude::*;
use ciphers::serpent;
use key_deriv::preparing_keys;
use key_deriv::rebuild_keys;
use keyring::Entry;
use memmap2::Mmap;
use ring::{self, rand::SecureRandom};
use slh_dsa::SlhDsaSignature;
use slh_dsa::params::SLH_DSA_SHAKE_256S;
use std::fs::File;
use std::io::Result;
use std::path::Path;
pub fn read_file_mmap<P: AsRef<std::path::Path>>(path: P) -> io::Result<Mmap> {
    let file = File::open(path)?;
    unsafe { Mmap::map(&file) }
}
pub fn read_file_fast<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}
fn write_file(file_path: &str, contents: &str) -> Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(contents.as_bytes())
}
fn write_fileb(file_path: &str, contents: &[u8]) -> Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(contents)
}
fn rand_byte(a: &mut [u8]) {
    let sr = ring::rand::SystemRandom::new();
    let _ = sr.fill(a);
}
fn main() {
    let (input, output, d, e, sigs_check) = parse_args();
    if e == true {
        encrypt(input, output);
    } else if d == true {
        decrypt(input, output, sigs_check);
    }
}
fn encrypt(input: String, output: String) {
    print!("enter pharsepass: ");
    io::stdout().flush().unwrap();
    let pharsepass = read_password().expect("eror while reading password");
    let (
        camellia_128_key,
        xchacha20_poly1305,
        ascon_aead128,
        serpent_key,
        twofish_key,
        threefish_key,
        aes_key,
        big_s,
    ) = preparing_keys(pharsepass);
    let (mut n0, mut n1, mut n2, mut n3, mut n4, mut n5, mut n6) = (
        [0u8; 16], [0u8; 16], [0u8; 16], [0u8; 24], [0u8; 16], [0u8; 12], [0u8; 128],
    );
    rand_byte(&mut n0);
    rand_byte(&mut n1);
    rand_byte(&mut n2);
    rand_byte(&mut n3);
    rand_byte(&mut n4);
    rand_byte(&mut n5);
    rand_byte(&mut n6);
    let mut seed = [0u8; 32];
    rand_byte(&mut seed);
    let mlsdsa_sk = mldsa_generatekey(seed);
    let slhdsa_ks = slhdsa_genratekeys();
    let data = read_file_mmap(input).expect("file read error");
    let mut r1 = camellia_encrypt(camellia_128_key, n0, &data);
    r1.extend_from_slice(&n0);
    let r21 = mldsa_sign(mlsdsa_sk.clone(), &r1);
    let r22 = r21.to_bytes().to_vec();
    let mut r3: Vec<u8> = Vec::with_capacity(r1.len() + r22.len());
    r3.extend_from_slice(&r1);
    r3.extend_from_slice(&r22);
    let mut r4 = ascon_encrypt(ascon_aead128, n1, &r3);
    r4.extend_from_slice(&n1);
    let mut r5 = serpent(serpent_key, &n2, &r4);
    r5.extend_from_slice(&n2);
    let mut r6 = xchacha20_encrypt(xchacha20_poly1305, n3, &r5);
    r6.extend_from_slice(&n3);
    let mut r7 = twofish256(twofish_key, &n4, &r6);
    r7.extend_from_slice(&n4);
    let mut r8 = aes_encrypt(&r7, &aes_key, n5);
    r8.extend_from_slice(&n5);
    let mut r9 = threefish_encrypt(&threefish_key, &r8, &n6);
    r9.extend_from_slice(&n6);
    let mut salts = [0u8; 256];
    salts[0..32].copy_from_slice(&big_s.0);
    salts[32..64].copy_from_slice(&big_s.1);
    salts[64..96].copy_from_slice(&big_s.2);
    salts[96..128].copy_from_slice(&big_s.3);
    salts[128..160].copy_from_slice(&big_s.4);
    salts[160..192].copy_from_slice(&big_s.5);
    salts[192..224].copy_from_slice(&big_s.6);
    salts[224..256].copy_from_slice(&big_s.7);
    r9.extend_from_slice(&salts);
    let r10 = slhdsa_sign(slhdsa_ks.clone(), &r9);
    r9.extend_from_slice(&r10.to_bytes().to_vec());
    let va1 = Entry::new("arypto", "ml-dsa key").expect("keyring error:");
    let _ = write_file(&output, &BASE64_STANDARD.encode(r9));
    let _ = va1.set_secret(&seed);
    let va2 = Entry::new("arypto", "slh-dsa s key").expect("keyring error:");
    let _ = va2.set_secret(&slhdsa_ks.clone().secret_key().to_vec());
    let va3 = Entry::new("arypto", "slh-dsa p key").expect("keyring error:");
    let _ = va3.set_secret(&slhdsa_ks.clone().public_key().to_vec());
}

fn decrypt(input: String, output: String, s: bool) {
    print!("enter pharsepass: ");
    io::stdout().flush().unwrap();
    let pharsepass = read_password().expect("eror while reading password");
    let data = BASE64_STANDARD
        .decode(read_file_mmap(input).expect("error"))
        .expect("error this");
    let r17: Vec<u8>;
    let result: &[u8];
    if !s {
        const N: usize = 29792;
        let r1 = &data[..data.len() - N];
        let slsig = &data[data.len() - N..];
        let slhdsa_sig = SlhDsaSignature::from_bytes(SLH_DSA_SHAKE_256S, slsig).expect("error 130");
        let va1 = Entry::new("arypto", "slh-dsa s key").expect("keyring error:");
        let slhdsa_sk = va1
            .get_secret()
            .expect("no pre-stored key found, but you can open this file without cheking signs ");
        let _ = va1.delete_credential();
        let va2 = Entry::new("arypto", "slh-dsa p key").expect("keyring error:");
        let slhdsa_pk = va2
            .get_secret()
            .expect("no pre-stored key found, but you can open this file without cheking signs ");
        let slhdsa_ks = SlhDsaKeyPair::from_bytes(SLH_DSA_SHAKE_256S, &slhdsa_pk, &slhdsa_sk)
            .expect("error 136");
        if !(slhdsa_verify(slhdsa_ks, slhdsa_sig, r1)) {
            panic!("SLH_DSA prof this message edited");
        }
        const N2: usize = 256;
        let big_s = &r1[r1.len() - N2..];
        let r2 = &r1[..r1.len() - N2];
        let (
            camellia_128_key,
            xchacha20_poly1305,
            ascon_aead128,
            serpent_key,
            twofish_key,
            threefish_key,
            aes_key,
        ) = rebuild_keys(
            pharsepass,
            big_s[0..32].try_into().expect("error 153"),
            big_s[32..64].try_into().expect("error 154"),
            big_s[64..96].try_into().expect("error 155"),
            big_s[96..128].try_into().expect("error 156"),
            big_s[128..160].try_into().expect("error 157"),
            big_s[160..192].try_into().expect("error 158"),
            big_s[192..224].try_into().expect("error 159"),
            big_s[224..256].try_into().expect("error 160"),
        );
        const N3: usize = 128;
        let nc1 = &r2[r2.len() - N3..].try_into().expect("error 163");
        let r3 = &r2[..r2.len() - N3];
        let r4 = threefish_encrypt(&threefish_key, r3, &nc1);
        const N4: usize = 12;
        let nc2 = &r4[r4.len() - N4..].try_into().expect("error 167");
        let r5 = &r4[..r4.len() - N4];
        let r6 = aes_decrypt(&r5, &aes_key, *nc2);
        const N5: usize = 16;
        let nc3 = &r6[r6.len() - N5..].try_into().expect("error 171");
        let r7 = &r6[..r6.len() - N5];
        let r8 = twofish256(twofish_key, nc3, r7);
        const N6: usize = 24;
        let nc4 = &r8[r8.len() - N6..].try_into().expect("error 175");
        let r9 = &r8[..r8.len() - N6];
        let r10 = xchacha20_decrypt(xchacha20_poly1305, *nc4, r9);
        const N7: usize = 16;
        let nc5 = &r10[r10.len() - N7..].try_into().expect("error 179");
        let r11 = &r10[..r10.len() - N7];
        let r12 = serpent(serpent_key, nc5, r11);
        const N8: usize = 16;
        let nc6 = &r12[r12.len() - N8..].try_into().expect("error 183");
        let r13 = &r12[..r12.len() - N8];
        let r14 = ascon_decrypt(ascon_aead128, *nc6, r13);
        const N9: usize = 4_627;
        let va3 = Entry::new("arypto", "ml-dsa key").expect("keyring error:");
        let binding = va3
            .get_secret()
            .expect("no pre-stored key found, but you can open this file without cheking signs ");
        let mldsa_seed = binding.as_array().expect("error");
        let mldsa_keys = SigningKey::<MlDsa87>::from_seed(mldsa_seed.into());
        let sig: &[u8; N9] = &r14[r14.len() - N9..].try_into().expect("error 190");
        let r15 = &r14[..r14.len() - N9].to_vec();
        let verfiyres = mldsa_verify(
            mldsa_keys,
            r15,
            Signature::<MlDsa87>::decode(sig.into()).expect("error 195"),
        );
        if !verfiyres {
            println!("ml_dsa sig says data have changes");
        }
        const N10: usize = 16;
        let nc7 = &r15[r15.len() - N10..].try_into().expect("error 201");
        let r16 = &r15[..r15.len() - N10];
        r17 = camellia_decrypt(camellia_128_key, *nc7, r16);
        result = &r17;
    } else {
        const N: usize = 29792;
        let r1 = &data[..data.len() - N];
        const N2: usize = 256;
        let big_s = &r1[r1.len() - N2..];
        let r2 = &r1[..r1.len() - N2];
        let (
            camellia_128_key,
            xchacha20_poly1305,
            ascon_aead128,
            serpent_key,
            twofish_key,
            threefish_key,
            aes_key,
        ) = rebuild_keys(
            pharsepass,
            big_s[0..32].try_into().expect("error 153"),
            big_s[32..64].try_into().expect("error 154"),
            big_s[64..96].try_into().expect("error 155"),
            big_s[96..128].try_into().expect("error 156"),
            big_s[128..160].try_into().expect("error 157"),
            big_s[160..192].try_into().expect("error 158"),
            big_s[192..224].try_into().expect("error 159"),
            big_s[224..256].try_into().expect("error 160"),
        );
        const N3: usize = 128;
        let nc1 = &r2[r2.len() - N3..].try_into().expect("error 163");
        let r3 = &r2[..r2.len() - N3];
        let r4 = threefish_encrypt(&threefish_key, r3, &nc1);
        const N4: usize = 12;
        let nc2 = &r4[r4.len() - N4..].try_into().expect("error 167");
        let r5 = &r4[..r4.len() - N4];
        let r6 = aes_decrypt(&r5, &aes_key, *nc2);
        const N5: usize = 16;
        let nc3 = &r6[r6.len() - N5..].try_into().expect("error 171");
        let r7 = &r6[..r6.len() - N5];
        let r8 = twofish256(twofish_key, nc3, r7);
        const N6: usize = 24;
        let nc4 = &r8[r8.len() - N6..].try_into().expect("error 175");
        let r9 = &r8[..r8.len() - N6];
        let r10 = xchacha20_decrypt(xchacha20_poly1305, *nc4, r9);
        const N7: usize = 16;
        let nc5 = &r10[r10.len() - N7..].try_into().expect("error 179");
        let r11 = &r10[..r10.len() - N7];
        let r12 = serpent(serpent_key, nc5, r11);
        const N8: usize = 16;
        let nc6 = &r12[r12.len() - N8..].try_into().expect("error 183");
        let r13 = &r12[..r12.len() - N8];
        let r14 = ascon_decrypt(ascon_aead128, *nc6, r13);
        const N9: usize = 4_627;
        let r15 = &r14[..r14.len() - N9].to_vec();
        const N10: usize = 16;
        let nc7 = &r15[r15.len() - N10..].try_into().expect("error 201");
        let r16 = &r15[..r15.len() - N10];
        r17 = camellia_decrypt(camellia_128_key, *nc7, r16);
        result = &r17;
    }

    let _ = write_fileb(&output, result);
}
