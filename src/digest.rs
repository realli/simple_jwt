use openssl::hash::{MessageDigest};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::memcmp::eq;
use base64::{encode_config, URL_SAFE};

use super::errors::{Result, JWTError};
use super::header::Algorithm;

fn create_message_digest(alg: Algorithm) -> MessageDigest {
    match alg {
        Algorithm::HS256 | Algorithm::RS256 => MessageDigest::sha256(),
        Algorithm::HS384 | Algorithm::RS384 => MessageDigest::sha384(),
        Algorithm::HS512 | Algorithm::RS512 => MessageDigest::sha512()
    }
}

pub fn hs_signature(secret: &str,
                 data: &str,
                 alg: Algorithm) -> Result<String> {
    _hs_signature(secret, data, alg).map(|u8s| encode_config(&u8s, URL_SAFE))
}

fn _hs_signature(secret: &str,
                 data: &str,
                 alg: Algorithm) -> Result<Vec<u8>> {
    let key = try!(PKey::hmac(secret.as_bytes()));
    let message_digest = create_message_digest(alg);
    let mut signer = try!(Signer::new(message_digest, &key));
    try!(signer.update(data.as_bytes()));
    let byte_vec = try!(signer.finish());
    Ok(byte_vec)
}

pub fn hs_verify(secret: &str,
                 data: &str,
                 sig: &[u8],
                 alg: Algorithm) -> Result<()> {
    let digest_u8s = &try!(_hs_signature(secret, data, alg));
    if digest_u8s.len() != sig.len()
        || !eq(digest_u8s, sig) {
        return Err(JWTError::InvalidSignature);
    }
    Ok(())
}

pub fn rsa_signature(pem_string: &str,
                     data: &str,
                     alg: Algorithm) -> Result<String> {

    let rsa = try!(Rsa::private_key_from_pem(pem_string.as_bytes()));
    let message_digest = create_message_digest(alg);
    let key = try!(PKey::from_rsa(rsa));
    let mut signer = try!(Signer::new(message_digest, &key));
    try!(signer.update(data.as_bytes()));
    let result = try!(signer.finish());
    return Ok(encode_config(&result, URL_SAFE));
}

pub fn rsa_verify(pem_string: &str,
                  data: &str,
                  sig: &[u8],
                  alg: Algorithm) -> Result<()> {
    let message_digest = create_message_digest(alg);
    let rsa = try!(Rsa::public_key_from_pem(pem_string.as_bytes()));
    let key = try!(PKey::from_rsa(rsa));
    let mut verifier = try!(Verifier::new(message_digest, &key));
    try!(verifier.update(data.as_bytes()));
    let b = try!(verifier.finish(sig));
    if b {
        Ok(())
    } else {
        Err(JWTError::InvalidSignature)
    }
}
