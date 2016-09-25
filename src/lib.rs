#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_json;
extern crate rustc_serialize;
extern crate crypto;

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
        let header = Header::default();
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
        let result = encode(&claim, "secret").unwrap();
        println!("hashed result is {}", result);
        let new_claim = decode(&result, "secret").unwrap();
        assert_eq!(claim, new_claim);
    }
}

pub use self::utils::JWTStringConvertable;
use self::header::{Header, Algorithm};
pub use self::claim::{Claim};
pub use self::errors::{JWTError, Result};
use self::digest::create_digest;

pub fn encode(body: &Claim, secret: &str) -> Result<String> {
    let header = Header::default();

    let header_base64 = try!(header.to_base64_str());
    let body_base64 = try!(body.to_base64_str());

    let secured_base64 = create_digest(secret, &header_base64, &body_base64);

    let mut jwt_base64 = header_base64 + "." + &body_base64;
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

    let verified_signature = match header.alg {
        Algorithm::HS256 => create_digest(secret, vec[0], vec[1]),
        // _ => return Err(JWTError::UnsupportAlgorithm),
    };

    if signature != &verified_signature {
        return Err(JWTError::InvalidSignature);
    }

    Ok(claim)
    // may be check claim fields ?
}
