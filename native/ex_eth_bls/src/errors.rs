use rustler::Error;

#[derive(Debug)]
pub enum BlsError {
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidInput,
    ZeroSizeInput,
    CryptoError,
}

impl From<BlsError> for Error {
    fn from(err: BlsError) -> Self {
        Error::Term(Box::new(format!("{:?}", err)))
    }
}
