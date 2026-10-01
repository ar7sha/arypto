pub mod skdf {
    use streebog::{Digest, Streebog256};

    fn streebog256(a: &[u8]) -> [u8; 32] {
        let mut hasher = Streebog256::new();
        hasher.update(a);
        hasher.finalize().into()
    }

    fn streebog_mac(input: impl AsRef<[u8]>, k: impl AsRef<[u8]>) -> [u8; 32] {
        let input = input.as_ref();
        let k = k.as_ref();
        let mut hk = [0u8; 32];
        let k2 = if k.len() > 64 {
            hk.copy_from_slice(&streebog256(k));
            &hk
        } else {
            k
        };
        let mut padded = [0x36; 64];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut ih = Streebog256::new();
        ih.update(&padded[..]);
        ih.update(input);

        for p in padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Streebog256::new();
        oh.update(&padded[..]);
        oh.update(ih.finalize());
        oh.finalize().into()
    }

    pub fn extract(salt: impl AsRef<[u8]>, ikm: impl AsRef<[u8]>) -> [u8; 32] {
        streebog_mac(ikm, salt)
    }

    pub fn expand(out: &mut [u8], prk: impl AsRef<[u8]>, info: impl AsRef<[u8]>) {
        let info = info.as_ref();
        let mut counter: u8 = 1;
        assert!(out.len() < 0xff * 32);
        let mut i: usize = 0;
        while i < out.len() {
            let mut hmac = Streebog256::new();
            hmac.update(&prk);
            if i != 0 {
                hmac.update(&out[i - 32..][..32]);
            }
            hmac.update(info);
            hmac.update([counter]);
            let left = core::cmp::min(32, out.len() - i);
            out[i..][..left].copy_from_slice(&hmac.finalize()[..left]);
            counter += 1;
            i += 32;
        }
    }
}

pub mod jkdf {
    use jh::{Digest, Jh256};
    fn jh2566(a: &[u8]) -> [u8; 32] {
        let mut hasher = Jh256::new();
        hasher.update(a);
        hasher.finalize().into()
    }

    fn jh256_mac(input: impl AsRef<[u8]>, k: impl AsRef<[u8]>) -> [u8; 32] {
        let input = input.as_ref();
        let k = k.as_ref();
        let mut hk = [0u8; 32];
        let k2 = if k.len() > 64 {
            hk.copy_from_slice(&jh2566(k));
            &hk
        } else {
            k
        };
        let mut padded = [0x36; 64];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut ih = Jh256::new();
        ih.update(&padded[..]);
        ih.update(input);

        for p in padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Jh256::new();
        oh.update(&padded[..]);
        oh.update(ih.finalize());
        oh.finalize().into()
    }

    pub fn extract(salt: impl AsRef<[u8]>, ikm: impl AsRef<[u8]>) -> [u8; 32] {
        jh256_mac(ikm, salt)
    }

    pub fn expand(out: &mut [u8], prk: impl AsRef<[u8]>, info: impl AsRef<[u8]>) {
        let info = info.as_ref();
        let mut counter: u8 = 1;
        assert!(out.len() < 0xff * 32);
        let mut i: usize = 0;
        while i < out.len() {
            let mut hmac = Jh256::new();
            hmac.update(&prk);
            if i != 0 {
                hmac.update(&out[i - 32..][..32]);
            }
            hmac.update(info);
            hmac.update([counter]);
            let left = core::cmp::min(32, out.len() - i);
            out[i..][..left].copy_from_slice(&hmac.finalize()[..left]);
            counter += 1;
            i += 32;
        }
    }
}
