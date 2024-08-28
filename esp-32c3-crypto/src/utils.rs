use crypto_bigint::Uint;
use esp_hal::{
    rsa::{
        operand_sizes::{Op1024, Op2048},
        Rsa,
        RsaModularExponentiation
    },
    Blocking
};

use crate::{
    error::{Error, Result},
    rsa::{RsaKey, RsaPrivateKey, RsaPublicKey},
    traits::{PrivateKeyParts, PublicKeyParts}
};


pub const fn compute_mprime<const N: usize>(modulus: &Uint<N>) -> u32 {
    let m_inv = modulus.inv_mod2k(32).to_words()[0];
    (-1 * m_inv as i64 % 4294967296) as u32
}

pub const fn compute_r<const LIMBS: usize>(modulus: &Uint<LIMBS>) 
-> Uint<LIMBS>
where [(); LIMBS * 2 + 1]: Sized 
{
    let mut d = [0_u32; LIMBS * 2 + 1];
    d[d.len() - 1] = 1;
    let d = Uint::from_words(d);
    d.const_rem(&modulus.resize()).0.resize()
}


fn run_expo_1024(
    rsa: &mut Rsa<Blocking>,
    exponent: &[u32; 32],
    modulus: &[u32; 32],
    m_prime: u32,
    base: &[u32; 32],
    r: &[u32; 32],
    output: &mut [u32; 32]
)
{
    let mut rsa_exp: RsaModularExponentiation<Op1024, Blocking> = RsaModularExponentiation::new(
        rsa,
        exponent,
        modulus,
        m_prime,
    );

    rsa_exp.start_exponentiation(base, r);
    rsa_exp.read_results(output);
}


fn run_expo_2048(
    rsa: &mut Rsa<Blocking>,
    exponent: &[u32; 64],
    modulus: &[u32; 64],
    m_prime: u32,
    base: &[u32; 64],
    r: &[u32; 64],
    output: &mut [u32; 64]
)
{
    let mut rsa_exp: RsaModularExponentiation<Op2048, Blocking> = RsaModularExponentiation::new(
        rsa,
        exponent,
        modulus,
        m_prime,
    );

    rsa_exp.start_exponentiation(base, r);
    rsa_exp.read_results(output);
}


pub fn rsa_decrypt<'a, T: RsaKey>(
    rsa: &mut esp_hal::rsa::Rsa<Blocking>,
    priv_key: &RsaPrivateKey<T>,
    base: &[u8],
    out: &'a mut [u8]
) -> Result<&'a [u8]>{
    match T::OperandWords {
        32 => {
            let base = unsafe { &*(base.as_ptr() as *const[u32; 32]) };
            let mut output_buffer = [0u32; 32];
            run_expo_1024(
                rsa,
                unsafe { core::mem::transmute(priv_key.d()) },
                unsafe { core::mem::transmute(priv_key.n()) },
                priv_key.mprime(),
                base,
                unsafe { core::mem::transmute(priv_key.r()) },
                &mut output_buffer
            );
            for (i, &b) in unsafe { core::mem::transmute::<[u32; 32] ,[u8; 128]>(output_buffer) }.iter().rev().enumerate() {
                out[i] = b;
            }

        },
        64 => {
            let base = unsafe { &*(base.as_ptr() as *const[u32; 64]) };
            let mut output_buffer = [0u32; 64];
            run_expo_2048(
                rsa,
                unsafe { core::mem::transmute(priv_key.d()) },
                unsafe { core::mem::transmute(priv_key.n()) },
                priv_key.mprime(),
                base,
                unsafe { core::mem::transmute(priv_key.r()) },
                &mut output_buffer
            );
            for (i, &b) in unsafe { core::mem::transmute::<[u32; 64] ,[u8; 256]>(output_buffer) }.iter().rev().enumerate() {
                out[i] = b;
            }
        },
        _ => {
            return Err(Error::Internal);
        }
    }

    Ok(&out[..T::BLOCKSIZE])
}


pub fn rsa_encrypt<'a, T: RsaKey>(
    rsa: &mut Rsa<Blocking>,
    pub_key: &RsaPublicKey<T>,
    base: &[u8],
    out: &'a mut [u8]
) -> Result<&'a [u8]> {
    match T::OperandWords {
        32 => {
            let base = unsafe { &*(base.as_ptr() as *const[u32; 32]) };
            let mut output_buffer = [0u32; 32];
            run_expo_1024(
                rsa,
                unsafe { core::mem::transmute(pub_key.e()) },
                unsafe { core::mem::transmute(pub_key.n()) },
                pub_key.mprime(),
                base,
                unsafe { core::mem::transmute(pub_key.r()) },
                &mut output_buffer
            );

            for (i, &b) in unsafe { core::mem::transmute::<[u32; 32] ,[u8; 128]>(output_buffer) }.iter().rev().enumerate() {
                out[i] = b;
            }
        },
        64 => {
            let base = unsafe { &*(base.as_ptr() as *const[u32; 64]) };
            let mut output_buffer = [0u32; 64];
            run_expo_2048(
                rsa,
                unsafe { core::mem::transmute(pub_key.e()) },
                unsafe { core::mem::transmute(pub_key.n()) },
                pub_key.mprime(),
                base,
                unsafe { core::mem::transmute(pub_key.r()) },
                &mut output_buffer
            );

            for (i, &b) in unsafe { core::mem::transmute::<[u32; 64] ,[u8; 256]>(output_buffer) }.iter().rev().enumerate() {
                out[i] = b;
            }
        },
        _ => {
            return Err(Error::Internal);
        }
    }

    Ok(&out[..T::BLOCKSIZE])
}

