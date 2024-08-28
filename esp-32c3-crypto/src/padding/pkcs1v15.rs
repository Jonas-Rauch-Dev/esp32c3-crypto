use crypto_bigint::subtle::ConstantTimeEq;
use esp_hal::{sha::ShaMode, Blocking};

use crate::{
    error::{Error, Result},
    hash::sha::HashAlgorithm,
    rsa::{RsaKey, RsaPrivateKey},
    traits::{PrivateKeyParts, PublicKeyParts, SignatureScheme}, utils
};


pub struct Pkcs1v15Sign 
{
    hash_len: usize,
    prefix: &'static[u8]
}

impl Pkcs1v15Sign 
{
    pub fn new<H: HashAlgorithm>() -> Self {
        Self { 
            hash_len: H::output_len,
            prefix: pkcs1v15_get_prefix::<H>(),
        }
    }
}

static SHA256PREFIX: &[u8] = &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
static SHA224PREFIX: &[u8] = &[0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c];
static SHA1PREFIX: &[u8] = &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];

fn pkcs1v15_get_prefix<HA: HashAlgorithm>() -> &'static [u8] {
    match HA::hash_algorithm {
        ShaMode::SHA1 => {
            SHA1PREFIX
        },
        ShaMode::SHA224 => {
            SHA224PREFIX
        },
        ShaMode::SHA256 => {
            SHA256PREFIX
        }
    }
}

impl<T> SignatureScheme<T> for Pkcs1v15Sign 
where 
    T: RsaKey,
    [(); T::BLOCKSIZE]: Sized,
{
    fn sign<'a>(
        &self,
        priv_key: &RsaPrivateKey<T>,
        rng: esp_hal::rng::Rng,
        rsa: &mut esp_hal::rsa::Rsa<Blocking>,
        digest_in: &[u8],
        signature_out: &'a mut [u8]
    ) 
    -> crate::error::Result<&'a [u8]> 
    {
        if digest_in.len() != self.hash_len {
            return Err(Error::InputNotHashed);
        }

        sign(rng, rsa, priv_key, &self.prefix, digest_in, signature_out)
    }

    fn verify(
        &self,
        pub_key: &crate::rsa::RsaPublicKey<T>,
        rsa: &mut esp_hal::rsa::Rsa<Blocking>,
        hashed: &[u8],
        sig: &[u8]
    ) -> Result<()> 
    {
        if sig.len() != T::BLOCKSIZE {
            return Err(Error::Verification);
        }

        let mut out_buffer = [0u8; T::BLOCKSIZE];
        let mut sig_buffer = [0u8; T::BLOCKSIZE];
        for (i, &b) in sig.iter().rev().enumerate() {
            sig_buffer[i] = b;
        }
        let encrypted = utils::rsa_encrypt(rsa, pub_key, &sig_buffer, &mut out_buffer)?;

        let hashlen = hashed.len();
        let t_len = self.prefix.len() + hashlen;
        let k = T::BLOCKSIZE;

        if k < t_len + 11 {
            return Err(Error::Verification);
        }

        let mut ok = encrypted[0].ct_eq(&0u8);
        ok &= encrypted[1].ct_eq(&1u8);
        ok &= encrypted[k - hashlen..k].ct_eq(hashed);
        ok &= encrypted[k - t_len..k - hashlen].ct_eq(self.prefix);
        ok &= encrypted[k - t_len - 1].ct_eq(&0u8);

        for el in encrypted.iter().skip(2).take(k - t_len - 3) {
            ok &= el.ct_eq(&0xff)
        }

        if ok.unwrap_u8() != 1 {
            return Err(Error::Verification);
        }

        Ok(())
    }
}


fn sign<'a, T: RsaKey>(
    rng: esp_hal::rng::Rng,
    rsa: &mut esp_hal::rsa::Rsa<Blocking>,
    priv_key: &RsaPrivateKey<T>,
    prefix: &[u8],
    digest_in: &[u8],
    signature_out: &'a mut [u8]
) -> Result<&'a [u8]>
where 
    [(); T::BLOCKSIZE]: Sized,
{
    // Write the unencrypted signature with padding to a temporary buffer
    let mut em_buffer = [0xffu8; T::BLOCKSIZE];
    let em = pkcs1v15_sign_pad(prefix, digest_in, T::BLOCKSIZE, &mut em_buffer)?;

    utils::rsa_decrypt(rsa, priv_key, &em, signature_out)
}


fn pkcs1v15_sign_pad<'a>(prefix: &[u8], digest_in: &[u8], k: usize, em: &'a mut [u8]) -> Result<&'a [u8]>{
    let hash_len = digest_in.len();
    let t_len = prefix.len() + digest_in.len();
    if k < t_len + 11 {
        return Err(Error::MessageTooLong);
    }

    let em_len = em.len();

    if em_len < k {
        return Err(Error::BufferTooSmall);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    em[k-1] = 0;
    em[k-2] = 1;
    em[0 + t_len] = 0;

    for (i, &b) in prefix.iter().enumerate() {
        em[t_len-1-i] = b;
    }
    for (i, &b) in digest_in.iter().enumerate() {
        em[hash_len-1-i] = b;
    }

    Ok(&em[0..k])
}