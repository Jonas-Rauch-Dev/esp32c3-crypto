use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use esp_hal::{rng::Rng, rsa::Rsa, sha::ShaMode, Blocking};
use zeroize::Zeroize;

use crate::{
    error::{Error, Result},
    hash::sha::HashAlgorithm,
    rsa::{Decrypt, Encrypt, RsaKey, RsaPrivateKey, RsaPublicKey},
    traits::{PaddingScheme, SignatureScheme}
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
    T: RsaKey<OperandType = [u32; T::OperandWords]>,
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
    where 
        T: Decrypt<T>
    {
        if digest_in.len() != self.hash_len {
            return Err(Error::InputNotHashed);
        }

        if signature_out.len() < T::BLOCKSIZE {
            return Err(Error::BufferTooSmall);
        }

        sign(rng, rsa, priv_key, &self.prefix, digest_in, signature_out)
    }

    fn verify(
        &self,
        pub_key: &crate::rsa::RsaPublicKey<T>,
        rsa: &mut esp_hal::rsa::Rsa<Blocking>,
        hashed: &[u8],
        sig: &[u8]
    )
    -> Result<()> 
    where 
        T: Encrypt<T>
    {
        if sig.len() != T::BLOCKSIZE {
            return Err(Error::Verification);
        }

        let mut out_buffer = [0u8; T::BLOCKSIZE];
        let mut sig_buffer = [0u8; T::BLOCKSIZE];
        for (i, &b) in sig.iter().rev().enumerate() {
            sig_buffer[i] = b;
        }
        let encrypted = T::encrypt(rsa, pub_key, &sig_buffer, &mut out_buffer)?;

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
    T: Decrypt<T> + RsaKey<OperandType = [u32; T::OperandWords]>
{
    // Write the unencrypted signature with padding to a temporary buffer
    let mut em_buffer = [0xffu8; T::BLOCKSIZE];
    let em = pkcs1v15_sign_pad(prefix, digest_in, T::BLOCKSIZE, &mut em_buffer)?;

    T::decrypt(rsa, priv_key, &em, signature_out)
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


pub struct Pkcs1v15Encrypt;

impl<T: RsaKey> PaddingScheme<T> for Pkcs1v15Encrypt 
where
    T: RsaKey<OperandType = [u32; T::OperandWords]>,
    [(); T::BLOCKSIZE]: Sized,
{
    fn encrypt<'a>(
        &self,
        rsa: &mut Rsa<Blocking>,
        rng: &mut Rng,
        pub_key: &RsaPublicKey<T>,
        plaintext: &[u8],
        ciphertext_buffer: &'a mut [u8]
    ) 
    -> Result<&'a [u8]>
    where 
        T: Encrypt<T>
    {
        if ciphertext_buffer.len() < T::BLOCKSIZE {
            return Err(Error::BufferTooSmall);
        }

        let mut em: [u8; T::BLOCKSIZE] = pkcs1v15_encrypt_pad_le(rng, plaintext)?;
        let result = T::encrypt(rsa, pub_key, &em, ciphertext_buffer)?;
        em.zeroize();
        Ok(result)
    }

    fn decrypt<'a>(
        &self,
        rsa: &mut Rsa<Blocking>,
        priv_key: &RsaPrivateKey<T>,
        ciphertext: &[u8],
        plaintext_buffer: &'a mut [u8]
    ) 
    -> Result<&'a [u8]>
    where
        T: Decrypt<T> {

            if plaintext_buffer.len() < T::BLOCKSIZE {
                return Err(Error::BufferTooSmall);
            }

            // Write ciphertext in le to cipher_buffer
            let mut cipher_buffer = [0u8; T::BLOCKSIZE];
            for (i, &b) in ciphertext.iter().rev().enumerate() {
                cipher_buffer[i] = b;
            }

            let mut buffer = [0u8; T::BLOCKSIZE];
            let decryption_result = T::decrypt(rsa, priv_key, &cipher_buffer, &mut buffer)?;

            let result = pkcs1v15_encrypt_unpad_be::<{T::BLOCKSIZE}>(decryption_result, plaintext_buffer)?;
            buffer.zeroize();
            cipher_buffer.zeroize();
            Ok(result)
        }
}


fn pkcs1v15_encrypt_pad_le<const K: usize>(rng: &mut Rng, plaintext: &[u8]) -> Result<[u8; K]> {
    if plaintext.len() > K - 11 {
        return Err(Error::MessageTooLong);
    }

    let mut out = [0u8; K];

    out[K - 2] = 2;
    non_zero_random_bytes(rng, &mut out[plaintext.len() + 1..K - 2]);
    out[plaintext.len()] = 0;
    for (i, &b) in plaintext.iter().rev().enumerate() {
        out[i] = b;
    }
    // out[..plaintext.len()].copy_from_slice(plaintext);
    Ok(out)
}


fn non_zero_random_bytes(rng: &mut Rng, out: &mut [u8]) {
    for i in 0..out.len() {
        loop {
            rng.read(&mut out[i..i+1]);
            if out[i] != 0 { break; }
        }
    }
}

fn pkcs1v15_encrypt_unpad_be<'a, const K: usize>(decryption_result: &[u8], plaintext_buffer: &'a mut [u8]) -> Result<&'a [u8]> {
    let first_byte_is_zero = decryption_result[0].ct_eq(&0u8);
    let second_byte_is_two = decryption_result[1].ct_eq(&2u8);

    let mut looking_for_index = 1u8;
    let mut index = 0u32;

    for (i, el) in decryption_result.iter().enumerate().skip(2) {
        let equals_zero = el.ct_eq(&0u8);
        index.conditional_assign(
            &(i as u32),
            Choice::from(looking_for_index) & equals_zero
        );
        looking_for_index.conditional_assign(&0u8, equals_zero);
    }

    let valid_ps = Choice::from((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid = first_byte_is_zero 
        & second_byte_is_two 
        & Choice::from(!looking_for_index & 1) & valid_ps;


    index = u32::conditional_select(
        &0, 
        &(index + 1), 
        valid
    );

    let idx = index as usize;

    plaintext_buffer[..K - idx].copy_from_slice(&decryption_result[idx..]);

    Ok(&plaintext_buffer[..K - idx])
}