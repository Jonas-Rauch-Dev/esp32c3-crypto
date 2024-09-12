
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    SPKIError(spki::Error),
    PKCS1Error(pkcs1::Error),
    PKCS8Error(pkcs8::Error),
    AlignmentError(&'static str),
    RsaKeySizeError,
    InputNotHashed,
    MessageTooLong,
    BufferTooSmall,
    Internal,
    Verification,
    InvalidBlockSize,
    InvalidEncoding,
}