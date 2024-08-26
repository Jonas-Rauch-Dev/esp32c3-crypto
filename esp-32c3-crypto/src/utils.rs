use crypto_bigint::Uint;
use esp_hal::{rsa::{Rsa, RsaMode, RsaModularExponentiation}, Blocking};


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


fn run_expo<T, const N: usize> (
    rsa: &mut Rsa<Blocking>,
    exponent: &[u32; N],
    modulus: &[u32; N],
    m_prime: u32,
    base: &[u32; N],
    r: &[u32; N],
    output: &mut [u32; N]
)
where
    T: RsaMode<InputType = [u32; N]>,
{
    let mut rsa_exp: RsaModularExponentiation<T, Blocking> = RsaModularExponentiation::new(
        rsa,
        exponent,
        modulus,
        m_prime,
    );

    rsa_exp.start_exponentiation(base, r);
    rsa_exp.read_results(output);
}