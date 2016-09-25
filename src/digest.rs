use crypto::hmac::{Hmac};
use crypto::sha2::Sha256;
use crypto::mac::Mac;
use rustc_serialize::base64::{ToBase64, URL_SAFE};

pub fn create_digest(secure: &str, header_base64: &str, claim_base64: &str) -> String {
    let digest = Sha256::new();
    let mut hmac = Hmac::new(digest, secure.as_bytes());
    hmac.input(header_base64.as_bytes());
    hmac.input(".".as_bytes());
    hmac.input(claim_base64.as_bytes());
    let result = hmac.result();
    let hashed = result.code().clone();
    hashed.to_base64(URL_SAFE)
}
