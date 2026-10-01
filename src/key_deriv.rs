mod kdf_streebog_jh;
use kdf_streebog_jh::jkdf;
use kdf_streebog_jh::skdf;
use ring::{self, rand::SecureRandom};
fn rand_byte(a: &mut [u8]) {
    let sr = ring::rand::SystemRandom::new();
    let _ = sr.fill(a);
}
pub fn preparing_keys(
    pharsepass: String,
) -> (
    [u8; 32],
    [u8; 32],
    [u8; 16],
    [u8; 32],
    [u8; 32],
    [u8; 128],
    [u8; 32],
    (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ),
) {
    fn blake3_pt(
        pharsepass: String,
    ) -> ([u8; 32], [u8; 32], [u8; 16], ([u8; 32], [u8; 32], [u8; 32])) {
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
    fn hkdf_pt(
        pharsepass: String,
    ) -> (
        [u8; 32],
        [u8; 32],
        [u8; 128],
        ([u8; 32], [u8; 32], [u8; 32]),
    ) {
        let mut salt1: [u8; 32] = [0; 32];
        rand_byte(&mut salt1);
        let mut salt2: [u8; 32] = [0; 32];
        rand_byte(&mut salt2);
        let mut salt3: [u8; 32] = [0; 32];
        rand_byte(&mut salt3);
        let info1 = "serpent 256 key";
        let info2 = "threefish 1024 key";
        let info3 = "twofish 256 key";
        let prk1 = hmac_sha256::HKDF::extract(salt1, pharsepass.clone());
        let mut serpent_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut serpent_key, prk1, info1);
        let prk2 = hmac_sha256::HKDF::extract(salt2, pharsepass.clone());
        let mut threefish_key = [0u8; 128];
        hmac_sha256::HKDF::expand(&mut threefish_key, prk2, info2);
        let prk3 = hmac_sha256::HKDF::extract(salt3, pharsepass.clone());
        let mut twofish_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut twofish_key, prk3, info3);
        let s = (salt1, salt2, salt3);
        (serpent_key, twofish_key, threefish_key, s)
    }
    fn shkdf_and_jhkdf_pt(pharsepass: String) -> ([u8; 32], ([u8; 32], [u8; 32])) {
        let mut salt: [u8; 32] = [0; 32];
        rand_byte(&mut salt);
        let context = format!("aes 256 gcm key {}", hex::encode(salt));
        let prk1 = skdf::extract(salt, pharsepass.clone());
        let mut a = [0u8; 32];
        skdf::expand(&mut a, prk1, &context);
        let mut salt2: [u8; 32] = [0; 32];

        rand_byte(&mut salt2);
        let context2 = format!("aes 256 gcm key {}", hex::encode(salt2));
        let prk2 = jkdf::extract(salt2, pharsepass.clone());
        let mut a2 = [0u8; 32];
        jkdf::expand(&mut a2, prk2, &context2);
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(format!("{}{}", hex::encode(a), hex::encode(a2)));
        let s = (salt, salt2);
        (hasher.finalize().into(), s)
    }
    let (a, b, c, blake3pt) = blake3_pt(pharsepass.clone());
    let (d, e, f, hkdfpt) = hkdf_pt(pharsepass.clone());
    let (g, sjkdf) = shkdf_and_jhkdf_pt(pharsepass);
    let s = (
        blake3pt.0, blake3pt.1, blake3pt.2, hkdfpt.0, hkdfpt.1, hkdfpt.2, sjkdf.0, sjkdf.1,
    );
    (a, b, c, d, e, f, g, s)
}

pub fn rebuild_keys(
    pharsepass: String,
    camel: [u8; 32],
    xchacha: [u8; 32],
    ascon: [u8; 32],
    serp: [u8; 32],
    twof: [u8; 32],
    threefi: [u8; 32],
    aes: [u8; 32],
    ae: [u8; 32],
) -> (
    [u8; 32],
    [u8; 32],
    [u8; 16],
    [u8; 32],
    [u8; 32],
    [u8; 128],
    [u8; 32],
) {
    fn blake3_pt(
        pharsepass: String,
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
        pharsepass: String,
        serp: [u8; 32],
        twof: [u8; 32],
        threefi: [u8; 32],
    ) -> ([u8; 32], [u8; 32], [u8; 128]) {
        let info1 = "serpent 256 key";
        let info2 = "threefish 1024 key";
        let info3 = "twofish 256 key";
        let prk1 = hmac_sha256::HKDF::extract(serp, pharsepass.clone());
        let mut serpent_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut serpent_key, prk1, info1);
        let prk2 = hmac_sha256::HKDF::extract(twof, pharsepass.clone());
        let mut threefish_key = [0u8; 128];
        hmac_sha256::HKDF::expand(&mut threefish_key, prk2, info2);
        let prk3 = hmac_sha256::HKDF::extract(threefi, pharsepass.clone());
        let mut twofish_key = [0u8; 32];
        hmac_sha256::HKDF::expand(&mut twofish_key, prk3, info3);
        (serpent_key, twofish_key, threefish_key)
    }
    fn shkdf_and_jhkdf_pt(pharsepass: String, aes: [u8; 32], ae: [u8; 32]) -> [u8; 32] {
        let context = format!("aes 256 gcm key {}", hex::encode(aes));
        let prk1 = skdf::extract(aes, pharsepass.clone());
        let mut a = [0u8; 32];
        skdf::expand(&mut a, prk1, &context);

        let context2 = format!("aes 256 gcm key {}", hex::encode(ae));
        let prk2 = jkdf::extract(ae, pharsepass.clone());
        let mut a2 = [0u8; 32];
        jkdf::expand(&mut a2, prk2, &context2);
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(format!("{}{}", hex::encode(a), hex::encode(a2)));
        hasher.finalize().into()
    }
    let (a, b, c) = blake3_pt(pharsepass.clone(), camel, xchacha, ascon);
    let (d, e, f) = hkdf_pt(pharsepass.clone(), serp, twof, threefi);
    let g = shkdf_and_jhkdf_pt(pharsepass, aes, ae);
    (a, b, c, d, e, f, g)
}
