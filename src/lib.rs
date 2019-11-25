//! # Introduction
//!
//! A very simple crate to deal with [json web token](http://jwt.io),
//! this lib use the `rust-openssl`, so you may want to check the
//! [rust-openssl](https://github.com/sfackler/rust-openssl) to find the
//! set-up of openssl runtime lib.
//!
//! # Support Algorithm
//!
//! * HS256/384/512
//! * RS256/384/512
//! * to be added...
//!
//! # Example
//!
//! ```
//! use simple_jwt::{encode, decode, Claim, Algorithm};
//!
//! let mut claim = Claim::default();
//! claim.set_iss("some iss");
//! claim.set_payload_field("stringhh", 12);
//! let result = encode(&claim, "secret", Algorithm::HS256).unwrap();
//! println!("hashed result is {}", result);
//! let new_claim = decode(&result, "secret").unwrap();
//! assert_eq!(claim, new_claim);
//!
//! ```
//!
//! Or simple use your custom struct
//!
//!
//! ```
//! #[macro_use]
//! extern crate serde_derive;
//! extern crate serde;
//! extern crate simple_jwt;
//!
//! use serde::{Serialize, Deserialize};
//! use simple_jwt::{encode, decode, Claim, Algorithm};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct MyStruct {
//!     field_u32: u32,
//!     field_str: String
//! }
//!
//! fn main() {
//!     let myStruct = MyStruct {field_str: String::from("hello"), field_u32: 32};
//!
//!     let result = encode(&myStruct, "secret", Algorithm::HS256).unwrap();
//!     println!("hashed result is {}", result);
//!     let newStruct = decode(&result, "secret").unwrap();
//!     assert_eq!(myStruct, newStruct);
//! }
//! ```
//!
//!
//! The test in lib.rs contains more example
//!
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate base64;
extern crate openssl;

mod errors;
mod utils;
mod header;
mod digest;
mod claim;


#[cfg(test)]
mod tests {
    use super::*;
    // A helper macro to compare error
    // copy from https://github.com/brson/error-chain/issues/95
    //
    // usage:
    // assert_error_kind!(some_err, ErrorKind::MyErrorType)
    macro_rules! assert_error_kind {
        ($err:expr, $kind:pat) => (match $err.kind() {
            &$kind => assert!(true, "{:?} is of kind {:?}", $err, stringify!($kind)),
            _     => assert!(false, "{:?} is NOT of kind {:?}", $err, stringify!($kind))
        });
    }

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        field_u32: u32,
        field_str: String
    }

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

        let s = TestStruct {field_u32: 32, field_str: String::from("hello")};
        let result = encode(&s, "secret", Algorithm::HS256).unwrap();
        let new_s: TestStruct = decode(&result, "secret").unwrap();
        assert_eq!(s.field_u32, new_s.field_u32);
        assert_eq!(s.field_str, new_s.field_str);
    }

    #[test]
    fn hs256_hs384_hs512_invalid_signature_should_be_recognized() {
        let mut claim = Claim::default();
        claim.set_iss("realli");
        claim.set_payload_field("stringhh", 12);
        let result = encode(&claim, "secret", Algorithm::HS256).unwrap();

        let vec: Vec<&str> = result.split('.').collect();
        assert_eq!(vec.len(), 3);
        let mut fake_jwt_str = vec[0].to_string();
        fake_jwt_str.push('.');
        fake_jwt_str.push_str(vec[1]);
        fake_jwt_str.push('.');
        fake_jwt_str.push_str("YWJj");
        fake_jwt_str.push_str(vec[2]);

        let new_claim: Result<Claim> = decode(&fake_jwt_str, "secret");
        assert!(new_claim.is_err());
        let err = new_claim.unwrap_err();
        assert_error_kind!(err, ErrorKind::InvalidSignature);
    }

    #[test]
    fn rsa256_384_512_should_work() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCx5gqY8ZZK5MNFHI5V1OYkNXI7
qFka5lHJcUFq6SaZqAXYteKcR4kugITcoILZIpVhM3yOp0octAackM2AOCGfo5Fo
E/W/iSrd8euMy4UkdtD6XfGYkkfO4yfhXpZjyvprhZ027p2X0l7eoRY3KycPYVF1
gC3TfsCAVObIW0MuBQIDAQAB
-----END PUBLIC KEY-----";
        let private_key_pem = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCx5gqY8ZZK5MNFHI5V1OYkNXI7qFka5lHJcUFq6SaZqAXYteKc
R4kugITcoILZIpVhM3yOp0octAackM2AOCGfo5FoE/W/iSrd8euMy4UkdtD6XfGY
kkfO4yfhXpZjyvprhZ027p2X0l7eoRY3KycPYVF1gC3TfsCAVObIW0MuBQIDAQAB
AoGAVO7oVlbZE06er8tPZUksy1K9BCB+0inuGEe7HMjNhgTDLdDArS42H356cD8t
2W76dJq5N/5EkumcUnmLs1CZNCt+xSVBL2ihS6LQm5k69vLqGlYMnKMRqAuQMr2C
61/nPgFEaqjjjVyI6yYLMcU2eG2NPoNPBJkjC9yERGlFta0CQQDYlzXtVVTKvhZB
Y4m8UD1GcLFz3cxOPHfs1DzgxxqcME7LeyQHhFkEiqKiUeDEccCMJ4oq9AKqUPvf
MgyAnKm/AkEA0kSOEJ1qwOgLcStmHh4Q9T7zPdnhsDacvBY2EHA248YYgEjOmUFd
5OQmiN9rtiB78E4wSNWSvsG8edQcjvWxOwJAQwrbOHGXY4JfZTIoak/0B5/Obe0T
1ovFG1u+1F0NEZeqbDXbuy/uVgeLu+7YQjZrwXZjwFPzl0CmFjppwE2+BQJBALbI
56Kj5Whaj4/KhVQLGPzIw1TyMhIn92o9+LOjiOPKkgP6xrZNL51JhAIaDp1dccA9
iBXYq19uNTTG4iiYhn8CQG9KpMDscoqocTeBE78jA6pX6ZH0Ppu7me5sds0UtwuS
p5HP/xmDtWJQv5hScT2aWKjjl2kC8eZOHTGgQvjrSm8=
-----END RSA PRIVATE KEY-----";
        /*
        let rsa_ = Rsa::generate(1024).unwrap();
        let private_key_pem_b = rsa_.private_key_to_pem().unwrap();
        let private_key_pem = &String::from_utf8(private_key_pem_b).unwrap();
        let public_key_pem_b = rsa_.public_key_to_pem().unwrap();
        let public_key_pem = &String::from_utf8(public_key_pem_b).unwrap();

        println!("\n\n {0} \n\n {1} \n\n", private_key_pem, public_key_pem);
        */

        let mut claim = Claim::default();
        claim.set_sub("1234567890");
        claim.set_payload_field("name", "John Doe");
        claim.set_payload_field("admin", true);
        let result0 = encode(&claim, private_key_pem, Algorithm::RS256).unwrap();
        let result1 = encode(&claim, private_key_pem, Algorithm::RS384).unwrap();
        let result2 = encode(&claim, private_key_pem, Algorithm::RS512).unwrap();
        /*
        println!("{}", result0);
        println!("{}", result1);
        println!("{}", result2);
        */
        let new_claim0 = decode(&result0, public_key_pem).unwrap();
        let new_claim1 = decode(&result1, public_key_pem).unwrap();
        let new_claim2 = decode(&result2, public_key_pem).unwrap();
        assert_eq!(claim, new_claim0);
        assert_eq!(claim, new_claim1);
        assert_eq!(claim, new_claim2);

        let s = TestStruct {field_u32: 32, field_str: String::from("hello")};
        let result = encode(&s, private_key_pem, Algorithm::RS512).unwrap();
        let new_s: TestStruct = decode(&result, public_key_pem).unwrap();
        assert_eq!(s.field_u32, new_s.field_u32);
        assert_eq!(s.field_str, new_s.field_str);
    }

    #[test]
    fn es_256_should_work() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbSDOGvmz9BjL+MBTnss0KOve0a/n
WvTCN3s52ZRZxpTnEifkoczAxRu4VNcdzsNPtAR1LsI2iBxccYHIJhRXyw==
-----END PUBLIC KEY-----";
        let private_key_pem = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHetHzlW7+nBW2dAtT4o4sK69aroXx1jgdMqEIfA9vtYoAoGCCqGSM49
AwEHoUQDQgAEbSDOGvmz9BjL+MBTnss0KOve0a/nWvTCN3s52ZRZxpTnEifkoczA
xRu4VNcdzsNPtAR1LsI2iBxccYHIJhRXyw==
-----END EC PRIVATE KEY-----";

        let mut claim = Claim::default();
        claim.set_sub("1234567890");
        claim.set_payload_field("name", "John Doe");
        claim.set_payload_field("admin", true);
        let result0 = encode(&claim, private_key_pem, Algorithm::ES256).unwrap();

        let new_claim0 = decode(&result0, public_key_pem).unwrap();
        assert_eq!(claim, new_claim0);

        let s = TestStruct {field_u32: 32, field_str: String::from("hello")};
        let result = encode(&s, private_key_pem, Algorithm::ES256).unwrap();
        let new_s: TestStruct = decode(&result, public_key_pem).unwrap();
        assert_eq!(s.field_u32, new_s.field_u32);
        assert_eq!(s.field_str, new_s.field_str);
    }

    #[test]
    fn es_384_should_work() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWQMeCMzEN4jRpVEqzRE4HLqJ0VcNmwfB
cJ8TJGbYVB+NYlvOww0SfGamFg1/WuQiWLvHnkjunIfVRo8UpvR/pHiEbEVcCjxn
dqlN7NI1GIJM2AKUM8HswrbKgVwSUyFt
-----END PUBLIC KEY-----";
        let private_key_pem = "-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBhHxsjfxeHA2y86fIX//UOTiHBRuTLlV3MqH2Qw+RTdc+ATmfgDejj
nY7uo3otsw6gBwYFK4EEACKhZANiAARZAx4IzMQ3iNGlUSrNETgcuonRVw2bB8Fw
nxMkZthUH41iW87DDRJ8ZqYWDX9a5CJYu8eeSO6ch9VGjxSm9H+keIRsRVwKPGd2
qU3s0jUYgkzYApQzwezCtsqBXBJTIW0=
-----END EC PRIVATE KEY-----";

        let mut claim = Claim::default();
        claim.set_sub("1234567890");
        claim.set_payload_field("name", "John Doe");
        claim.set_payload_field("admin", true);
        let result0 = encode(&claim, private_key_pem, Algorithm::ES384).unwrap();

        let new_claim0 = decode(&result0, public_key_pem).unwrap();
        assert_eq!(claim, new_claim0);

        let s = TestStruct {field_u32: 32, field_str: String::from("hello")};
        let result = encode(&s, private_key_pem, Algorithm::ES384).unwrap();
        let new_s: TestStruct = decode(&result, public_key_pem).unwrap();
        assert_eq!(s.field_u32, new_s.field_u32);
        assert_eq!(s.field_str, new_s.field_str);
    }

    #[test]
    fn es_512_should_work() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAEcaMCeNLvbnbmEBuccJWW1QZkW9n
fnxqBSYW2vDuQgef2B9zwPbVDpeyejZkrwmAqYfDje0uKBnJNWs542yfsSIAv0vs
YmYlwJv2HA776oUORD8XN8zviZnHF4eK9Kv1B3LZLdQ+vYr6Hzo+sGnRiZYmpTaq
/Yd72ds/0BDuSVLUwy8=
-----END PUBLIC KEY-----";
        let private_key_pem = "-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEF2aTwJeJnQBAxYGEr+8fJqunk1+DUHSmNgafR5wqSVJEyZRnantoqo
aAgVAGYW+69mIAo8LtEX6lbnGn6tON7N4qAHBgUrgQQAI6GBiQOBhgAEABHGjAnj
S72525hAbnHCVltUGZFvZ358agUmFtrw7kIHn9gfc8D21Q6Xsno2ZK8JgKmHw43t
LigZyTVrOeNsn7EiAL9L7GJmJcCb9hwO++qFDkQ/FzfM74mZxxeHivSr9Qdy2S3U
Pr2K+h86PrBp0YmWJqU2qv2He9nbP9AQ7klS1MMv
-----END EC PRIVATE KEY-----";

        let mut claim = Claim::default();
        claim.set_sub("1234567890");
        claim.set_payload_field("name", "John Doe");
        claim.set_payload_field("admin", true);
        let result0 = encode(&claim, private_key_pem, Algorithm::ES512).unwrap();

        let new_claim0 = decode(&result0, public_key_pem).unwrap();

        assert_eq!(claim, new_claim0);

        let s = TestStruct {field_u32: 32, field_str: String::from("hello")};
        let result = encode(&s, private_key_pem, Algorithm::ES512).unwrap();
        let new_s: TestStruct = decode(&result, public_key_pem).unwrap();
        assert_eq!(s.field_u32, new_s.field_u32);
        assert_eq!(s.field_str, new_s.field_str);
    }
}

use base64::{decode_config, URL_SAFE};

pub use self::header::{Header, Algorithm};
pub use self::claim::Claim;
pub use self::utils::JWTStringConvertable;
pub use self::errors::*;
use self::digest::{hs_signature, hs_verify,
                   rsa_signature, rsa_verify,
                   ecdsa_signature, ecdsa_verify};

/// encode a Claim to jwt string, if you are using RS256/384/512, secret should be your private key
pub fn encode<T: JWTStringConvertable>(body: &T, secret: &str, alg: Algorithm) -> Result<String> {
    let header = Header::new(alg);

    let header_base64 = header.to_base64_str()?;
    let body_base64 = body.to_base64_str()?;

    let mut jwt_base64 = header_base64 + "." + &body_base64;
    let secured_base64 = match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            => hs_signature(secret, &jwt_base64, header.alg),
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
            => rsa_signature(secret, &jwt_base64, header.alg),
        Algorithm::ES256 | Algorithm::ES384 | Algorithm:: ES512
            => ecdsa_signature(secret, &jwt_base64, header.alg),
    }?;
    jwt_base64.push('.');
    jwt_base64.push_str(&secured_base64);
    Ok(jwt_base64)
}

/// decode a jwt string using algorithm in the jwt header field
pub fn decode<T: JWTStringConvertable>(jwtstr: &str, secret: &str) -> Result<T> {
    let vec: Vec<&str> = jwtstr.split('.').collect();
    if vec.len() != 3 {
        return Err(ErrorKind::InvalidFormat.into());
    }

    // decode header first
    let header = Header::from_base64_str(vec[0])?;
    let claim = T::from_base64_str(vec[1])?;

    let mut data = vec[0].to_string();
    data.push('.');
    data.push_str(vec[1]);

    let sig = decode_config(&vec[2], URL_SAFE)?;

    match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            => hs_verify(secret, &data, &sig, header.alg),
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
            => rsa_verify(secret, &data, &sig, header.alg),
        Algorithm::ES256 | Algorithm::ES384 | Algorithm:: ES512
            => ecdsa_verify(secret, &data, &sig, header.alg),
    }?;
    Ok(claim)
}
