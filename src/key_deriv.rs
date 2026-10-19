mod kdf_streebog_jh;
use argon2::{Algorithm, Argon2, Params, Version};
use kdf_streebog_jh::jkdf;
use kdf_streebog_jh::skdf;
use ring::{self, rand::SecureRandom};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
fn rand_byte(a: &mut [u8]) {
    let sr = ring::rand::SystemRandom::new();
    let _ = sr.fill(a);
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub camellia_128_key: [u8; 32],
    pub xchacha20_poly1305: [u8; 32],
    pub ascon_aead128: [u8; 16],
    pub serpent_key: [u8; 32],
    pub twofish_key: [u8; 32],
    pub threefish_key: [u8; 128],
    pub aes_key: [u8; 32],
}
pub type BigS = [[u8; 32]; 9];
pub fn preparing_keys(pharsepass: &str) -> (Zeroizing<Keys>, BigS) {
    type Camel = [u8; 32];
    type Chacha = [u8; 32];
    type Ascon = [u8; 16];
    type Salts = ([u8; 32], [u8; 32], [u8; 32]);
    fn blake3_pt(pharsepass: &str) -> (Camel, Chacha, Ascon, Salts) {
        let mut salt1: [u8; 32] = [0; 32];
        rand_byte(&mut salt1);
        let mut salt2: [u8; 32] = [0; 32];
        rand_byte(&mut salt2);
        let mut salt3: [u8; 32] = [0; 32];
        rand_byte(&mut salt3);
        let context1 = format!("camellia 256 CTR key {}", hex::encode(salt1));
        let context2 = format!("xchacha20 poly1305 key {}", hex::encode(salt2));
        let context3 = format!("ascon AEAD128 key {}", hex::encode(salt3));
        let s = (salt1, salt2, salt3);
        let camellia_key_128 = blake3::derive_key(&context1, pharsepass.as_bytes());
        let xchacha20_poly1305 = blake3::derive_key(&context2, pharsepass.as_bytes());
        let mut ascon_aead12: [u8; 16] = [0; 16];
        ascon_aead12.copy_from_slice(&blake3::derive_key(&context3, pharsepass.as_bytes())[..16]);
        (camellia_key_128, xchacha20_poly1305, ascon_aead12, s)
    }
    fn hkdf_pt(pharsepass: &str) -> ([u8; 32], [u8; 32], [u8; 128], Salts) {
        let mut salt1: [u8; 32] = [0; 32];
        rand_byte(&mut salt1);
        let mut salt2: [u8; 32] = [0; 32];
        rand_byte(&mut salt2);
        let mut salt3: [u8; 32] = [0; 32];
        rand_byte(&mut salt3);
        let info1 = "serpent 256 key";
        let info2 = "threefish 1024 key";
        let info3 = "twofish 256 key";
        let prk1 = hmac_sha256::HKDF::extract(salt1, pharsepass);
        let prk2 = hmac_sha256::HKDF::extract(salt2, pharsepass);
        let prk3 = hmac_sha256::HKDF::extract(salt3, pharsepass);

        let mut serpent_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut serpent_key, prk1, info1);
        let mut threefish_key = [0u8; 128];
        hmac_sha256::HKDF::expand(&mut threefish_key, prk2, info2);
        let mut twofish_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut twofish_key, prk3, info3);
        let s = (salt1, salt2, salt3);
        (serpent_key, twofish_key, threefish_key, s)
    }
    fn shkdf_and_jhkdf_pt(pharsepass: &str) -> ([u8; 32], ([u8; 32], [u8; 32])) {
        let mut salt: [u8; 32] = [0; 32];
        rand_byte(&mut salt);
        let mut salt2: [u8; 32] = [0; 32];
        rand_byte(&mut salt2);

        let prk2 = jkdf::extract(salt2, pharsepass);
        let prk1 = skdf::extract(salt, pharsepass);

        let context = format!("aes 256 gcm key {}", hex::encode(salt));
        let mut a = [0u8; 32];
        skdf::expand(&mut a, prk1, &context);

        let context2 = format!("aes 256 gcm key {}", hex::encode(salt2));
        let mut a2 = [0u8; 32];
        jkdf::expand(&mut a2, prk2, &context2);

        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(a);
        a.zeroize();
        hasher.update(a2);
        a2.zeroize();
        let s = (salt, salt2);
        (hasher.finalize().into(), s)
    }
    let (a, b, c, blake3pt) = blake3_pt(pharsepass);
    let (d, e, f, hkdfpt) = hkdf_pt(pharsepass);
    let (g, sjkdf) = shkdf_and_jhkdf_pt(pharsepass);
    let s: BigS = [
        blake3pt.0, blake3pt.1, blake3pt.2, hkdfpt.0, hkdfpt.1, hkdfpt.2, sjkdf.0, sjkdf.1,
        [0u8; 32],
    ];
    (
        Zeroizing::new(Keys {
            camellia_128_key: a,
            xchacha20_poly1305: b,
            ascon_aead128: c,
            serpent_key: d,
            twofish_key: e,
            threefish_key: f,
            aes_key: g,
        }),
        s,
    )
}

pub fn rebuild_keys(pharsepass: &str, s: BigS) -> Keys {
    fn blake3_pt(
        pharsepass: &str,
        camel: [u8; 32],
        xchacha: [u8; 32],
        ascon: [u8; 32],
    ) -> ([u8; 32], [u8; 32], [u8; 16]) {
        let context1 = format!("camellia 256 CTR key {}", hex::encode(camel));
        let context2 = format!("xchacha20 poly1305 key {}", hex::encode(xchacha));
        let context3 = format!("ascon AEAD128 key {}", hex::encode(ascon));
        let camellia_key_128 = blake3::derive_key(&context1, pharsepass.as_bytes());
        let xchacha20_poly1305 = blake3::derive_key(&context2, pharsepass.as_bytes());
        let mut ascon_aead12: [u8; 16] = [0; 16];
        ascon_aead12.copy_from_slice(&blake3::derive_key(&context3, pharsepass.as_bytes())[..16]);
        (camellia_key_128, xchacha20_poly1305, ascon_aead12)
    }
    fn hkdf_pt(
        pharsepass: &str,
        serp: [u8; 32],
        twof: [u8; 32],
        threefi: [u8; 32],
    ) -> ([u8; 32], [u8; 32], [u8; 128]) {
        let info1 = "serpent 256 key";
        let info2 = "threefish 1024 key";
        let info3 = "twofish 256 key";
        let prk1 = hmac_sha256::HKDF::extract(serp, pharsepass);
        let mut serpent_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut serpent_key, prk1, info1);
        let prk2 = hmac_sha256::HKDF::extract(twof, pharsepass);
        let mut threefish_key = [0u8; 128];
        hmac_sha256::HKDF::expand(&mut threefish_key, prk2, info2);
        let prk3 = hmac_sha256::HKDF::extract(threefi, pharsepass);
        let mut twofish_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut twofish_key, prk3, info3);
        (serpent_key, twofish_key, threefish_key)
    }
    fn shkdf_and_jhkdf_pt(pharsepass: &str, aes: [u8; 32], ae: [u8; 32]) -> [u8; 32] {
        let context = format!("aes 256 gcm key {}", hex::encode(aes));
        let prk1 = skdf::extract(aes, pharsepass);
        let mut a = [0u8; 32];
        skdf::expand(&mut a, prk1, &context);

        let context2 = format!("aes 256 gcm key {}", hex::encode(ae));
        let prk2 = jkdf::extract(ae, pharsepass);
        let mut a2 = [0u8; 32];
        jkdf::expand(&mut a2, prk2, &context2);
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(a);
        a.zeroize();
        hasher.update(a2);
        a2.zeroize();
        hasher.finalize().into()
    }
    let (a, b, c) = blake3_pt(pharsepass, s[0], s[1], s[2]);
    let (d, e, f) = hkdf_pt(pharsepass, s[3], s[4], s[5]);
    let g = shkdf_and_jhkdf_pt(pharsepass, s[6], s[7]);
    Keys {
        camellia_128_key: a,
        xchacha20_poly1305: b,
        ascon_aead128: c,
        serpent_key: d,
        twofish_key: e,
        threefish_key: f,
        aes_key: g,
    }
}

const M_COST: u32 = 65536; // 64 MiB
const T_COST: u32 = 3;
const P_COST: u32 = 4;
const HASH_LEN: usize = 32;

pub fn argon(password: &str) -> [[u8; 32]; 2] {
    let params = Params::new(M_COST, T_COST, P_COST, Some(HASH_LEN)).expect("error invalid input");
    let argon2id = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut argonsalt = [0u8; 32];
    rand_byte(&mut argonsalt);
    let mut pass = [0u8; HASH_LEN];
    let _ = argon2id.hash_password_into(password.as_bytes(), &argonsalt, &mut pass);
    [pass, argonsalt]
}
pub fn argon_rebuild(password: &str, salt: [u8; 32]) -> [u8; 32] {
    let params = Params::new(M_COST, T_COST, P_COST, Some(HASH_LEN)).expect("error invalid input");
    let argon2id = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut pass = [0u8; HASH_LEN];
    let _ = argon2id.hash_password_into(password.as_bytes(), &salt, &mut pass);
    pass
}
