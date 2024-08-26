use core::marker::PhantomData;

use crypto_bigint::Uint;
use pkcs8::PrivateKeyInfo;
use pkcs1::RsaPrivateKey as RsaPrivate;

use super::RsaKey;
use crate::error::{Result, Error};



#[derive(Debug)]
pub struct RsaPrivateKey <T: RsaKey> {
    d: T::OperandType,
    n: T::OperandType,
    m_prime: u32,
    r: T::OperandType,
    phantom: PhantomData<T>
}

impl<T: RsaKey> RsaPrivateKey <T> {
    pub fn new_from_der(private_key_der:&[u8])
    -> Result<Self>
    where 
        [(); T::OperandWords]: Sized,
        [(); T::OperandWords * 2 + 1]: Sized,
        T: RsaKey<OperandType = [u32; T::OperandWords]>
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

        Ok( Self {
            d: d.into(), n: n.into(), m_prime, r: r.into(), phantom: PhantomData
        })
    }
}