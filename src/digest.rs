use openssl::hash::{MessageDigest};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::memcmp::eq;
use base64::{encode_config, URL_SAFE};

use super::errors::*;
use super::header::Algorithm;
use super::utils::{
    ecdsa_der_to_raw,
    ecdsa_raw_to_der,
    P256_ORDER_LEN,
    P384_ORDER_LEN,
    P521_ORDER_LEN,
};

fn create_message_digest(alg: Algorithm) -> MessageDigest {
    match alg {
        Algorithm::HS256
            | Algorithm::RS256
            | Algorithm::ES256 => MessageDigest::sha256(),
        Algorithm::HS384
            | Algorithm::RS384
            | Algorithm::ES384 => MessageDigest::sha384(),
        Algorithm::HS512
            | Algorithm::RS512
            | Algorithm::ES512 => MessageDigest::sha512()
    }
}

fn get_order_len(alg:Algorithm) -> usize {
    match alg {
        Algorithm::ES256 => P256_ORDER_LEN,
        Algorithm::ES384 => P384_ORDER_LEN,
        Algorithm::ES512 => P521_ORDER_LEN,
        _ => panic!("get_order_len should not be called using algorithm besides ES256/384/512")
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
    let key = PKey::hmac(secret.as_bytes())?;
    let message_digest = create_message_digest(alg);
    let mut signer = Signer::new(message_digest, &key)?;
    signer.update(data.as_bytes())?;
    let byte_vec = signer.sign_to_vec()?;
    Ok(byte_vec)
}

pub fn hs_verify(secret: &str,
                 data: &str,
                 sig: &[u8],
                 alg: Algorithm) -> Result<()> {
    let digest_u8s = &_hs_signature(secret, data, alg)?;
    if digest_u8s.len() != sig.len()
        || !eq(digest_u8s, sig) {
        return Err(ErrorKind::InvalidSignature.into());
    }
    Ok(())
}

pub fn rsa_signature(pem_string: &str,
                     data: &str,
                     alg: Algorithm) -> Result<String> {

    let rsa = Rsa::private_key_from_pem(pem_string.as_bytes())?;
    let message_digest = create_message_digest(alg);
    let key = PKey::from_rsa(rsa)?;
    let mut signer = Signer::new(message_digest, &key)?;
    signer.update(data.as_bytes())?;
    let result = signer.sign_to_vec()?;
    Ok(encode_config(&result, URL_SAFE))
}

pub fn rsa_verify(pem_string: &str,
                  data: &str,
                  sig: &[u8],
                  alg: Algorithm) -> Result<()> {
    let message_digest = create_message_digest(alg);
    let rsa = Rsa::public_key_from_pem(pem_string.as_bytes())?;
    let key = PKey::from_rsa(rsa)?;
    let mut verifier = Verifier::new(message_digest, &key)?;
    verifier.update(data.as_bytes())?;
    let b = verifier.verify(sig)?;
    if b {
        Ok(())
    } else {
        Err(ErrorKind::InvalidSignature.into())
    }
}

pub fn ecdsa_signature(pem_string: &str,
                       data: &str,
                       alg: Algorithm) -> Result<String> {
    let key = PKey::private_key_from_pem(pem_string.as_bytes())?;
    let message_digest = create_message_digest(alg);
    let mut signer = Signer::new(message_digest, &key)?;
    signer.update(data.as_bytes())?;
    let result = signer.sign_to_vec()?;
    let raw_result = ecdsa_der_to_raw(&result, get_order_len(alg))?;
    Ok(encode_config(&raw_result, URL_SAFE))
}

pub fn ecdsa_verify(pem_string: &str,
                    data: &str,
                    sig: &[u8],
                    alg: Algorithm) -> Result<()> {
    let message_digest = create_message_digest(alg);
    let key = PKey::public_key_from_pem(pem_string.as_bytes())?;
    let mut verifier = Verifier::new(message_digest, &key)?;
    verifier.update(data.as_bytes())?;

    let der_sig = ecdsa_raw_to_der(sig, get_order_len(alg))?;
    let b = verifier.verify(&der_sig)?;
    if b {
        Ok(())
    } else {
        Err(ErrorKind::InvalidSignature.into())
    }
}
