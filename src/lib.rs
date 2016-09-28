#![cfg_attr(feature = "serde_macros", feature(plugin, custom_derive))]
#![cfg_attr(feature = "serde_macros", plugin(serde_macros))]

//! # Introduction
//!
//! A very simple crate to deal with [json web token](http://jwt.io), 
//! this lib use the `rust-openssl`, so you may want to check the
//! [rust-openssl](https://github.com/sfackler/rust-openssl) to find the
//! set-up of openssl runtime lib. 
//!
//! # Support Algirithm
//!
//! * HS256/384/512
//! * RS256/384/512
//! * to be added...
//!
//! # Example
//!
//! ```
//! use simple_jwt::{encode, decode, Claim, Algorithm};
//! let mut claim = Claim::default();
//! claim.set_iss("some iss");
//! claim.set_payload_field("stringhh", 12);
//! let result = encode(&claim, "secret", Algorithm::HS256).unwrap();
//! println!("hashed result is {}", result);
//! let new_claim = decode(&result, "secret").unwrap();
//! assert_eq!(claim, new_claim);
//! ```
//!
//! The test in lib.rs contains more example
//!

extern crate serde;
extern crate serde_json;
extern crate rustc_serialize;
extern crate openssl;

mod errors;
mod utils;
mod header;
mod digest;
mod claim;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_can_be_convert_from_and_to_base64() {
        let header = Header::new(Algorithm::default());
        let b_string = header.to_base64_str().unwrap();
        let new_header = Header::from_base64_str(&b_string).unwrap();
        assert_eq!(header, new_header);
    }

    #[test]
    fn claim_can_be_convert_form_and_to_base64() {
        let mut claim = Claim::default();
        claim.set_iss("realli");
        let b_string = claim.to_base64_str().unwrap();
        println!("bstring is {}",b_string);
        let mut new_claim = Claim::from_base64_str(&b_string).unwrap();
        new_claim.set_iss("realli");
        assert_eq!(claim, new_claim);
    }

    #[test]
    fn encoding_and_decoding_should_work_back_forth() {
        let mut claim = Claim::default();
        claim.set_iss("realli");
        claim.set_payload_field("stringhh", 12);
        let result = encode(&claim, "secret", Algorithm::default()).unwrap();
        println!("hashed result is {}", result);
        let new_claim = decode(&result, "secret").unwrap();
        assert_eq!(claim, new_claim);
    }

    #[test]
    fn hs256_hs384_hs512_should_work() {
        let mut claim = Claim::default();
        claim.set_iss("realli");
        claim.set_payload_field("stringhh", 12);
        let result0 = encode(&claim, "secret", Algorithm::HS256).unwrap();
        let result1 = encode(&claim, "secret", Algorithm::HS384).unwrap();
        let result2 = encode(&claim, "secret", Algorithm::HS512).unwrap();
        let new_claim0 = decode(&result0, "secret").unwrap();
        let new_claim1 = decode(&result1, "secret").unwrap();
        let new_claim2 = decode(&result2, "secret").unwrap();
        assert_eq!(claim, new_claim0);
        assert_eq!(claim, new_claim1);
        assert_eq!(claim, new_claim2);
    }

    #[test]
    fn rsa256_384_512_should_work() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----";
        let private_key_pem = "-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----";

        let mut claim = Claim::default();
        claim.set_payload_field("sub", "1234567890");
        claim.set_payload_field("name", "John Doe");
        claim.set_payload_field("admin", true);
        let result0 = encode(&claim, private_key_pem, Algorithm::RS256).unwrap();
        let result1 = encode(&claim, private_key_pem, Algorithm::RS384).unwrap();
        let result2 = encode(&claim, private_key_pem, Algorithm::RS512).unwrap();
        println!("{}", result0);
        println!("{}", result1);
        println!("{}", result2);
        let new_claim0 = decode(&result0, public_key_pem).unwrap();
        let new_claim1 = decode(&result1, public_key_pem).unwrap();
        let new_claim2 = decode(&result2, public_key_pem).unwrap();
        assert_eq!(claim, new_claim0);
        assert_eq!(claim, new_claim1);
        assert_eq!(claim, new_claim2);
    }

}

pub use self::utils::JWTStringConvertable;
pub use self::header::{Header, Algorithm};
pub use self::claim::{Claim};
pub use self::errors::{JWTError, Result};
use self::digest::{hs_signature, hs_verify, rsa_signature, rsa_verify};
use openssl::crypto::hash::Type;
use rustc_serialize::base64::FromBase64;

/// encode a Claim to jwt string, if you are using RS256/384/512, secret should be your private key
pub fn encode(body: &Claim, secret: &str, alg: Algorithm) -> Result<String> {
    let header = Header::new(alg);

    let header_base64 = try!(header.to_base64_str());
    let body_base64 = try!(body.to_base64_str());

    let mut jwt_base64 = header_base64 + "." + &body_base64;
    let secured_base64 = try!(match header.alg {
        Algorithm::HS256 => hs_signature(secret, &jwt_base64, Type::SHA256),
        Algorithm::HS384 => hs_signature(secret, &jwt_base64, Type::SHA384),
        Algorithm::HS512 => hs_signature(secret, &jwt_base64, Type::SHA512),
        Algorithm::RS256 => rsa_signature(secret, &jwt_base64, Type::SHA256),
        Algorithm::RS384 => rsa_signature(secret, &jwt_base64, Type::SHA384),
        Algorithm::RS512 => rsa_signature(secret, &jwt_base64, Type::SHA512),
    });
    jwt_base64.push('.');
    jwt_base64.push_str(&secured_base64);
    Ok(jwt_base64)
}

/// decode a jwt string using algorithm in the jwt header field
pub fn decode(jwtstr: &str, secret: &str) -> Result<Claim> {
    let vec: Vec<&str> = jwtstr.split('.').collect();
    if vec.len() != 3 {
        return Err(JWTError::InvalidFormat);
    }

    // decode header first
    let header = try!(Header::from_base64_str(vec[0]));
    let claim = try!(Claim::from_base64_str(vec[1]));

    let mut data = vec[0].to_string();
    data.push('.');
    data.push_str(vec[1]);

    let sig = try!(vec[2].from_base64());

    try!(match header.alg {
        Algorithm::HS256 => hs_verify(secret, &data, &sig, Type::SHA256),
        Algorithm::HS384 => hs_verify(secret, &data, &sig, Type::SHA384),
        Algorithm::HS512 => hs_verify(secret, &data, &sig, Type::SHA512),
        Algorithm::RS256 => rsa_verify(secret, &data, &sig, Type::SHA256),
        Algorithm::RS384 => rsa_verify(secret, &data, &sig, Type::SHA384),
        Algorithm::RS512 => rsa_verify(secret, &data, &sig, Type::SHA512),
    });

    Ok(claim)
    // may be check claim fields ?
}
