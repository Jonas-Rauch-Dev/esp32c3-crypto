use core::marker::PhantomData;

use crate::{error::{Error, Result}, traits::{PaddingScheme, PublicKeyParts, SignatureScheme}};


use crypto_bigint::Uint;
use esp_hal::{rng::Rng, rsa::Rsa, Blocking};
use spki::SubjectPublicKeyInfoRef;
use pkcs1::RsaPublicKey as RsaPubKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Encrypt, RsaKey};


#[derive(Debug)]
pub struct RsaPublicKey<T: RsaKey> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    d: T::OperandType,
    n: T::OperandType,
    m_prime: u32,
    r: T::OperandType,
    phantom: PhantomData<T>
}

impl<T: RsaKey> RsaPublicKey<T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    pub fn new_from_der(bytes: &[u8])
    -> Result<Self>
    where 
        [(); T::OperandWords]: Sized,
        [(); {T::OperandWords} * 2 + 1]: Sized,
        [(); T::BLOCKSIZE]: Sized,
    {
        // Parse the public keys bytes to rust data structure
        let pub_key_info = SubjectPublicKeyInfoRef::try_from(bytes)
            .map_err(|e| Error::SPKIError(e) )?; 

        let pub_key_bytes = match pub_key_info.subject_public_key.as_bytes() {
            Some(pkb) => Ok(pkb),
            None => Err(Error::AlignmentError("Subject public key BIT STRING has unused bits")),
        }?;

        let pub_key: RsaPubKey = RsaPubKey::try_from(pub_key_bytes)
            .map_err(|e| Error::PKCS1Error(e))?;

        let modulus_bytes = pub_key.modulus.as_bytes();

        if modulus_bytes.len() != T::BLOCKSIZE {
            return Err(Error::RsaKeySizeError)
        }

        let n: Uint<{T::OperandWords}> = Uint::from_be_slice(modulus_bytes);
        let m_prime = crate::utils::compute_mprime(&n);
        let r: Uint<{T::OperandWords}> = crate::utils::compute_r::<{T::OperandWords}>(&n);

        let d_bytes = pub_key.public_exponent.as_bytes();
        let mut d_buffer: [u8; T::BLOCKSIZE] = [0u8; T::BLOCKSIZE];
        let start_index = T::BLOCKSIZE - d_bytes.len();
        d_buffer[start_index..].copy_from_slice(&d_bytes);
        let d: Uint<{T::OperandWords}> = Uint::from_be_slice(&d_buffer);

        Ok (Self {
            d: d.into(), n: n.into(), m_prime, r: r.into(), phantom: PhantomData
        })
    }
}


impl<T: RsaKey> RsaPublicKey<T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    pub fn encrypt<
        'a, P: PaddingScheme<T>
    >(
        &self, rsa: &mut Rsa<Blocking>, rng: &mut Rng, padding: &P, plaintext: &[u8], ciphertext_buffer: &'a mut [u8]
    ) 
    -> Result<&'a [u8]>
    where 
        T: Encrypt<T>
    {
        padding.encrypt(rsa, rng, self, plaintext, ciphertext_buffer)
    }

    pub fn verify<S: SignatureScheme<T>>(
        &self, rsa: &mut Rsa<Blocking>, padding: S, hashed: &[u8], sig: &[u8]
    ) -> Result<()> 
    where
        S: SignatureScheme<T>,
        T: Encrypt<T>
    {
        padding.verify(self, rsa, hashed, sig)
    }
}

impl<T: RsaKey> PublicKeyParts<T> for RsaPublicKey<T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{
    fn e(&self) -> &<T as RsaKey>::OperandType {
        &self.d
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

impl<T: RsaKey> Zeroize for RsaPublicKey<T> where T: RsaKey<OperandType = [u32; T::OperandWords]> {
    fn zeroize(&mut self) {
        for i in 0..T::OperandWords {
            self.d[i] = 0;
            self.n[i] = 0;
            self.r[i] = 0;
        }

        self.m_prime.zeroize();
        self.phantom.zeroize();
    }
}


impl<T> Drop for RsaPublicKey<T> 
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]> 
{
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<T> ZeroizeOnDrop for RsaPublicKey<T>
where 
    T: RsaKey<OperandType = [u32; T::OperandWords]>
{}