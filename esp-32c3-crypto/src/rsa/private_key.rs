use core::marker::PhantomData;

use base64::Engine;
use crypto_bigint::Uint;
use esp_hal::{rng::Rng, rsa::Rsa, Blocking};
use pkcs8::PrivateKeyInfo;
use pkcs1::RsaPrivateKey as RsaPrivate;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Decrypt, RsaKey};
use crate::{error::{Error, Result}, traits::{PaddingScheme, PrivateKeyParts, PublicKeyParts, SignatureScheme}};



#[derive(Debug)]
pub struct RsaPrivateKey <T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]> 
{
    d: T::OperandType,
    n: T::OperandType,
    m_prime: u32,
    r: T::OperandType,
    e: T::OperandType,
    phantom: PhantomData<T>
}

impl<T> RsaPrivateKey <T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>,
    [(); T::OperandWords]: Sized,
    [(); T::OperandWords * 2 + 1]: Sized,
    [(); T::BLOCKSIZE]: Sized,
{
    pub fn new_from_der(private_key_der:&[u8])
    -> Result<Self>
    {
        // Parse private key bytes to rust data structure
        let priv_key_info = PrivateKeyInfo::try_from(private_key_der)
            .map_err(|e| Error::PKCS8Error(e))?;

        let priv_key = RsaPrivate::try_from(priv_key_info.private_key)
            .map_err(|e| Error::PKCS1Error(e))?;

        let modulus_bytes = priv_key.modulus.as_bytes();

        if modulus_bytes.len() != T::BLOCKSIZE {
            return Err(Error::RsaKeySizeError);
        }

        // Extract needed values from key and convert them to U1024
        let n: Uint<{T::OperandWords}> = Uint::from_be_slice(modulus_bytes);
        let d: Uint<{T::OperandWords}> = Uint::from_be_slice(priv_key.private_exponent.as_bytes());
        let m_prime = crate::utils::compute_mprime(&n);
        let r: Uint<{T::OperandWords}> = crate::utils::compute_r(&n);


        let e_bytes = priv_key.public_exponent.as_bytes();
        let mut e_buffer: [u8; T::BLOCKSIZE] = [0u8; T::BLOCKSIZE];
        let start_index = T::BLOCKSIZE - e_bytes.len();
        e_buffer[start_index..].copy_from_slice(&e_bytes);
        let e: Uint<{T::OperandWords}> = Uint::from_be_slice(&e_buffer);

        Ok( Self {
            d: d.into(), n: n.into(), m_prime, r: r.into(), e: e.into(), phantom: PhantomData
        })
    }

    pub fn new_from_b64_der(string: &str) -> Result<Self> {
        let mut bytes = [0u8; 4096];
        let written_bytes = match base64::prelude::BASE64_STANDARD.decode_slice(string, &mut bytes) {
            Ok(wb) => wb,
            Err(e) => {
                match e {
                    base64::DecodeSliceError::DecodeError(_) => return Err(Error::InvalidEncoding),
                    base64::DecodeSliceError::OutputSliceTooSmall => return Err(Error::RsaKeySizeError)
                }
            }
        };

        return Self::new_from_der(&bytes[..written_bytes]);
    }
}

impl<T> PrivateKeyParts<T> for RsaPrivateKey<T>
where
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    fn d(&self) -> &<T as RsaKey>::OperandType {
        &self.d
    }
}

impl<T> PublicKeyParts<T> for RsaPrivateKey<T> 
where
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    fn e(&self) -> &<T as RsaKey>::OperandType {
        &self.e
    }

    fn mprime(&self) -> u32 {
        self.m_prime
    }

    fn n(&self) -> &<T as RsaKey>::OperandType {
        &self.n
    }

    fn r(&self) -> &<T as RsaKey>::OperandType {
        &self.r
    }
}


impl<T> RsaPrivateKey <T> 
where
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    pub fn decrypt<'a, P: PaddingScheme<T>>(
        &self, rsa: &mut Rsa<Blocking>, padding: &P, ciphertext: &[u8], plaintext_buffer: &'a mut [u8]
    ) -> Result<&'a [u8]> 
    where 
        T: Decrypt<T>
    {
        padding.decrypt(rsa, self, ciphertext, plaintext_buffer)
    }

    pub fn sign<'a, S>(
        &self, rng: Rng, rsa: &mut Rsa<Blocking>, scheme: &S, digest_in: &[u8], signature_out: &'a mut [u8]) -> Result<&'a [u8]>
    where
        S: SignatureScheme<T>,
        T: Decrypt<T>
    {
        scheme.sign(self, rng, rsa, digest_in, signature_out)
    }
}

impl<T: RsaKey> Zeroize for RsaPrivateKey<T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]> 
{
    fn zeroize(&mut self) {
        for i in 0..T::OperandWords {
            self.d[i] = 0;
            self.n[i] = 0;
            self.r[i] = 0;
            self.e[i] = 0;
        }

        self.m_prime.zeroize();
        self.phantom.zeroize();
    }
}

impl<T> Drop for RsaPrivateKey<T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]> 
{
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<T> ZeroizeOnDrop for RsaPrivateKey<T>
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{}