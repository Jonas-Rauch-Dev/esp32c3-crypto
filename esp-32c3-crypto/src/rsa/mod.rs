mod publick_key;
use esp_hal::{rsa::Rsa, Blocking};
pub use publick_key::RsaPublicKey;

use crate::{
    error::{Result, Error},
    traits::{PrivateKeyParts, PublicKeyParts},
};

mod private_key;
pub use private_key::RsaPrivateKey;

use paste::paste;

pub trait RsaKey {
    const BLOCKSIZE: usize;
    type OperandType;
    const OperandWords: usize;
    const KEYSIZE: usize;
}

pub trait Encrypt<T: RsaKey>{
    fn encrypt<'a>(
        rsa: &mut Rsa<Blocking>,
        pub_key: &RsaPublicKey<T>,
        base: &[u8],
        out: &'a mut [u8]
    ) -> Result<&'a [u8]>;
}

pub trait Decrypt<T: RsaKey>{
    fn decrypt<'a>(
        rsa: &mut Rsa<Blocking>,
        priv_key: &RsaPrivateKey<T>,
        base: &[u8],
        out: &'a mut [u8]
    ) -> Result<&'a [u8]>;
}

macro_rules! implement_rsakey {
    (($x: literal)) => {
        paste! {
            #[derive(Debug)]
            pub struct [<RsaKeySize $x>];
        }
        paste! {
            impl RsaKey for [<RsaKeySize $x>] {
                const BLOCKSIZE: usize = $x / 8;
                type OperandType = [u32; $x / 32];
                const OperandWords: usize = $x / 32;
                const KEYSIZE: usize = $x;
            }

            impl Encrypt<[<RsaKeySize $x>]> for [<RsaKeySize $x>] {
                fn encrypt<'a>(
                    rsa: &mut Rsa<Blocking>,
                    pub_key: &RsaPublicKey<[<RsaKeySize $x>]>,
                    base: &[u8],
                    out: &'a mut [u8]
                ) -> Result<&'a [u8]> {
                    if base.len() != Self::BLOCKSIZE {
                        return Err(Error::InvalidBlockSize);
                    }
                    let base = unsafe { &*(base.as_ptr() as *const[u32; Self::OperandWords]) };
                    let mut output_buffer = [0u32; Self::OperandWords];


                    crate::utils::[<run_expo_ $x>](
                        rsa,
                        pub_key.e(),
                        pub_key.n(),
                        pub_key.mprime(),
                        base,
                        pub_key.r(),
                        &mut output_buffer
                    );
                    for (i, &b) in unsafe { core::mem::transmute::<[u32; Self::OperandWords] ,[u8; Self::BLOCKSIZE]>(output_buffer) }.iter().rev().enumerate() {
                        out[i] = b;
                    }

                    Ok(&out[..Self::BLOCKSIZE])
                }
            }

            impl Decrypt<[<RsaKeySize $x>]> for [<RsaKeySize $x>] {
                fn decrypt<'a>(
                    rsa: &mut Rsa<Blocking>,
                    priv_key: &RsaPrivateKey<[<RsaKeySize $x>]>,
                    base: &[u8],
                    out: &'a mut [u8]
                ) -> Result<&'a [u8]> {
                    let base = unsafe { &*(base.as_ptr() as *const[u32; Self::OperandWords]) };
                    let mut output_buffer = [0u32; Self::OperandWords];
                    crate::utils::[<run_expo_ $x>](
                        rsa,
                        unsafe { core::mem::transmute(priv_key.d()) },
                        unsafe { core::mem::transmute(priv_key.n()) },
                        priv_key.mprime(),
                        base,
                        unsafe { core::mem::transmute(priv_key.r()) },
                        &mut output_buffer
                    );

                    for (i, &b) in unsafe { core::mem::transmute::<[u32; Self::OperandWords] ,[u8; Self::BLOCKSIZE]>(output_buffer) }.iter().rev().enumerate() {
                        out[i] = b;
                    }

                    Ok(&out[..Self::BLOCKSIZE])
                }
            }
        }
    };

    ($x:tt, $($y:tt),+) => {
        implement_rsakey!($x);
        implement_rsakey!($($y),+);
    };
}


implement_rsakey!(
    (1024),
    (2048)
);