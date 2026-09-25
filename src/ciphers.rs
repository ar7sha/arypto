use cipher::KeyIvInit;
use ctr::cipher::{InnerIvInit, KeyInit, StreamCipher, StreamCipherCoreWrapper};
use ctr::{CtrCore, flavors};
use serpent::Serpent;
use slh_dsa::SlhDsaSignature;
use slh_dsa::params::SLH_DSA_SHAKE_256S;
use slh_dsa::safe_api::SlhDsaKeyPair;
use threefish::Threefish1024;
use twofish::Twofish;

pub mod camellia {
    use noxtls_crypto::{CamelliaCipher, noxtls_camellia_ctr_decrypt, noxtls_camellia_ctr_encrypt};

    pub fn camellia_encrypt(key: [u8; 32], nonce: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let cipher = CamelliaCipher::noxtls_new(&key).expect("error in camellia cipher");
        let ciphertext = noxtls_camellia_ctr_encrypt(&cipher, &nonce, plaintext);
        ciphertext
    }
    pub fn camellia_decrypt(key: [u8; 32], nonce: [u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = CamelliaCipher::noxtls_new(&key).expect("error in camellia cipher");
        let plaintext = noxtls_camellia_ctr_decrypt(&cipher, &nonce, ciphertext);
        plaintext
    }
}

pub mod mldsa {
    use ml_dsa::{Keypair, MlDsa87, Signature, Signer, SigningKey, Verifier};

    pub fn mldsa_generatekey(seed: [u8; 32]) -> SigningKey<MlDsa87> {
        let sk = SigningKey::<MlDsa87>::from_seed(&seed.into());
        sk
    }
    pub fn mldsa_sign(sk: SigningKey<MlDsa87>, msg: &[u8]) -> Signature<MlDsa87> {
        let sig = sk.sign(msg);
        sig
    }
    pub fn mldsa_verify(sk: SigningKey<MlDsa87>, msg: &[u8], sig: Signature<MlDsa87>) -> bool {
        sk.verifying_key().verify(msg, &sig).is_ok()
    }
}
pub mod ascon128 {
    use ascon_aead::aead::{Aead, KeyInit};
    use ascon_aead::{AsconAead128, AsconAead128Key, AsconAead128Nonce};
    pub fn ascon_encrypt(key: [u8; 16], nonce: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let k = AsconAead128Key::from_slice(&key);
        let cipher = AsconAead128::new(k);
        let nonce = AsconAead128Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("encryption failure!(ascon)");
        ciphertext
    }
    pub fn ascon_decrypt(key: [u8; 16], nonce: [u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        let k = AsconAead128Key::from_slice(&key);
        let cipher = AsconAead128::new(k);
        let nonce = AsconAead128Nonce::from_slice(&nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!");
        plaintext
    }
}
pub mod xchacha20 {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };
    pub fn xchacha20_encrypt(key: [u8; 32], nonce: [u8; 24], plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher.encrypt(&nonce.into(), plaintext);
        ciphertext.expect("error")
    }
    pub fn xchacha20_decrypt(key: [u8; 32], nonce: [u8; 24], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&key.into());
        let plaintext = cipher.decrypt(&nonce.into(), ciphertext);
        plaintext.expect("error")
    }
}

pub mod aes256 {
    use aes_gcm::{
        Aes256Gcm,
        aead::{Aead, KeyInit},
    };
    pub fn aes_encrypt(plaintext: &[u8], key: &[u8; 32], nonce: [u8; 12]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key.into());
        let ciphertext = cipher.encrypt(&nonce.into(), plaintext).expect("error");
        ciphertext
    }
    pub fn aes_decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: [u8; 12]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key.into());
        let plaintext = cipher.decrypt(&nonce.into(), ciphertext).expect("error");
        plaintext
    }
}
pub fn serpent(key: [u8; 32], nonce: &[u8; 16], text: &[u8]) -> Vec<u8> {
    let block = Serpent::new_from_slice(&key).expect("len invalid");
    let core = CtrCore::<Serpent, flavors::Ctr128BE>::inner_iv_init(block, nonce.into());
    let mut cipher = StreamCipherCoreWrapper::from_core(core);
    let mut buffer = text.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn twofish256(key: [u8; 32], nonce: &[u8; 16], text: &[u8]) -> Vec<u8> {
    let block = Twofish::new_from_slice(&key).expect("len invalid");
    let core = CtrCore::<Twofish, flavors::Ctr128BE>::inner_iv_init(block, nonce.into());
    let mut cipher = StreamCipherCoreWrapper::from_core(core);
    let mut buffer = text.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

type Threefish1024Ctr = ctr::Ctr128BE<Threefish1024>;
pub fn threefish_encrypt(key: &[u8; 128], text: &[u8], nonce: &[u8; 128]) -> Vec<u8> {
    let mut cipher = Threefish1024Ctr::new(key.into(), nonce.into());
    let mut buffer = text.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn slhdsa_genratekeys() -> SlhDsaKeyPair {
    SlhDsaKeyPair::generate(SLH_DSA_SHAKE_256S).unwrap()
}
pub fn slhdsa_sign(kp: SlhDsaKeyPair, msg: &[u8]) -> SlhDsaSignature {
    kp.sign(msg).unwrap()
}
pub fn slhdsa_verify(kp: SlhDsaKeyPair, sig: SlhDsaSignature, msg: &[u8]) -> bool {
    slh_dsa::safe_api::SlhDsaSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        msg.into(),
        SLH_DSA_SHAKE_256S,
    )
}
