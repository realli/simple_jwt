use openssl::crypto::hmac::hmac;
use openssl::crypto::hash::Type;
use rustc_serialize::base64::{ToBase64, URL_SAFE};

use super::errors::{Result, JWTError};


pub fn hs_digest(secret: &str,
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
