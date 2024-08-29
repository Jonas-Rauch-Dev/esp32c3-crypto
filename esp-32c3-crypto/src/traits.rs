use esp_hal::rng::Rng;
use esp_hal::Blocking;

use crate::rsa::{Encrypt, Decrypt, RsaKey, RsaPrivateKey, RsaPublicKey};
use crate::error::Result;

pub trait PaddingScheme<T: RsaKey> where T: RsaKey<OperandType = [u32; T::OperandWords]> {
    fn decrypt<'a>(self, priv_key: &RsaPrivateKey<T>, ciphertext: &[u8], plaintext_buffer: &'a [u8]) -> Result<&'a [u8]>;
    fn encrypt<'a>(self, rng: Rng, pub_key: &RsaPublicKey<T>, plaintext: &[u8], ciphertext_buffer: &'a [u8]) -> Result<&'a [u8]>;
}

pub trait SignatureScheme<T: RsaKey> where T: RsaKey<OperandType = [u32; T::OperandWords]>{
    fn sign<'a>(
        &self, priv_key: &RsaPrivateKey<T>, rng: Rng, rsa: &mut esp_hal::rsa::Rsa<Blocking>, digest_in: &[u8], signature_out: &'a mut [u8]
    ) -> Result<&'a [u8]>
    where 
        T: Decrypt<T>;

    fn verify(
        &self, pub_key: &RsaPublicKey<T>, rsa: &mut esp_hal::rsa::Rsa<Blocking>, hahsed: &[u8], sig: &[u8]
    ) -> Result<()>
    where
        T: Encrypt<T>;
}

pub trait PrivateKeyParts<T: RsaKey> {
    /// Returns the private exponent of the key.
    fn d(&self) -> &T::OperandType;
}

pub trait PublicKeyParts<T: RsaKey> {
    /// Returns the modulus of the key.
    fn n(&self) -> &T::OperandType;

    /// Returns the public exponent of the key.
    fn e(&self) -> &T::OperandType;

    /// Returns the pre calculated mrpime used for hw acceleration
    fn mprime(&self) -> u32;

    /// Returns the precomputed r for hw acceleration
    fn r(&self) -> &T::OperandType;
}