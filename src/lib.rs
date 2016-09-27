#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

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
    use super::header::*;
    use serde_json::value::{to_value};

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
        claim.iss("realli");
        let b_string = claim.to_base64_str().unwrap();
        println!("bstring is {}",b_string);
        let mut new_claim = Claim::from_base64_str(&b_string).unwrap();
        new_claim.iss("realli");
        assert_eq!(claim, new_claim);
    }

    #[test]
    fn encoding_and_decoding_should_work_back_forth() {
        let mut claim = Claim::default();
        claim.iss("realli");
        claim.payload.insert("stringhh".to_string(), to_value(12));
        let result = encode(&claim, "secret", Algorithm::default()).unwrap();
        println!("hashed result is {}", result);
        let new_claim = decode(&result, "secret").unwrap();
        assert_eq!(claim, new_claim);
    }

    #[test]
    fn hs256_hs384_hs512_should_work() {
        let mut claim = Claim::default();
        claim.iss("realli");
        claim.payload.insert("stringhh".to_string(), to_value(12));
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

}

pub use self::utils::JWTStringConvertable;
use self::header::{Header, Algorithm};
pub use self::claim::{Claim};
pub use self::errors::{JWTError, Result};
use self::digest::hs_digest;
use openssl::crypto::hash::Type;

pub fn encode(body: &Claim, secret: &str, alg: Algorithm) -> Result<String> {
    let header = Header::new(alg);

    let header_base64 = try!(header.to_base64_str());
    let body_base64 = try!(body.to_base64_str());

    let mut jwt_base64 = header_base64 + "." + &body_base64;
    let secured_base64 = try!(match header.alg {
        Algorithm::HS256 => hs_digest(secret, &jwt_base64, Type::SHA256),
        Algorithm::HS384 => hs_digest(secret, &jwt_base64, Type::SHA384),
        Algorithm::HS512 => hs_digest(secret, &jwt_base64, Type::SHA512),
    });
    jwt_base64.push('.');
    jwt_base64.push_str(&secured_base64);
    Ok(jwt_base64)
}

pub fn decode(jwtstr: &str, secret: &str) -> Result<Claim> {
    let vec: Vec<&str> = jwtstr.split('.').collect();
    if vec.len() != 3 {
        return Err(JWTError::InvalidFormat);
    }

    let signature = vec[2];
    // decode header first
    let header = try!(Header::from_base64_str(vec[0]));
    let claim = try!(Claim::from_base64_str(vec[1]));

    let mut data = vec[0].to_string();
    data.push('.');
    data.push_str(vec[1]);

    let verified_signature = try!(match header.alg {
        Algorithm::HS256 => hs_digest(secret, &data, Type::SHA256),
        Algorithm::HS384 => hs_digest(secret, &data, Type::SHA384),
        Algorithm::HS512 => hs_digest(secret, &data, Type::SHA512)
    });

    if signature != &verified_signature {
        return Err(JWTError::InvalidSignature);
    }

    Ok(claim)
    // may be check claim fields ?
}
