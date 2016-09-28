use openssl::crypto::hmac::hmac;
use openssl::crypto::hash::{Type, hash};
use openssl::crypto::rsa::RSA;
use rustc_serialize::base64::{ToBase64, URL_SAFE};

use super::errors::{Result, JWTError};


pub fn hs_signature(secret: &str,
                 data: &str,
                 t: Type) -> Result<String> {
    match t {
        Type::SHA256 | Type::SHA384 | Type::SHA512 
            => {
                let byte_vec = try!(hmac(t, secret.as_bytes(), data.as_bytes())
                                 .map_err(JWTError::CryptoFailure));
                return Ok(byte_vec.to_base64(URL_SAFE));
            },
        _ => return Err(JWTError::UnsupportAlgorithm),
    }
}

pub fn hs_verify(secret: &str,
                 data: &str,
                 sig: &[u8],
                 t: Type) -> Result<()> {
    let digest = try!(hs_signature(secret, data, t));
    if digest != sig.to_base64(URL_SAFE) {
        return Err(JWTError::InvalidSignature);
    }
    Ok(())
}

pub fn rsa_signature(pem_string: &str,
                     data: &str,
                     t: Type) -> Result<String> {
    let rsa = try!(RSA::private_key_from_pem(pem_string.as_bytes()).map_err(JWTError::CryptoFailure));
    match t {
        Type::SHA256 | Type::SHA384 | Type::SHA512 
            => {
                let byte_vec = try!(hash(t, data.as_bytes())
                                    .map_err(JWTError::CryptoFailure));
                let result = try!(rsa.sign(t, &byte_vec).map_err(JWTError::CryptoFailure));
                return Ok(result.to_base64(URL_SAFE));
            },
        _ => return Err(JWTError::UnsupportAlgorithm),
    }
}

pub fn rsa_verify(pem_string: &str,
                  data: &str,
                  sig: &[u8],
                  t: Type) -> Result<()> {
    let rsa = try!(RSA::public_key_from_pem(pem_string.as_bytes()).map_err(JWTError::CryptoFailure));
    match t {
        Type::SHA256 | Type::SHA384 | Type::SHA512 
            => {
                let byte_vec = try!(hash(t, data.as_bytes())
                                    .map_err(JWTError::CryptoFailure));
                try!(rsa.verify(t, &byte_vec, sig)
                     .map_err(JWTError::CryptoFailure));
                return Ok(());
            },
        _ => return Err(JWTError::UnsupportAlgorithm),
    }
}
