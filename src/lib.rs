#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_json;
extern crate rustc_serialize;

mod header;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_can_be_convert_from_and_to_base64() {
        let header = Header::default();
        let b_string = header.to_base64_str();
        let new_header = Header::from_base64_str(&b_string);
        assert_eq!(header, new_header);
    }
}


use std::default::Default;
use serde_json::value::{Map, Value};
use serde::{Serialize, Deserialize};

pub use self::header::{Header, Algorithm};


#[derive(Debug, Serialize, Deserialize)]
struct RegisteredClaim {
    exp: Option<u32>,
    nbf: Option<u32>,
    iat: Option<u32>,
    iss: Option<String>,
    aud: Option<String>,
    prn: Option<String>,
    jti: Option<String>,
    typ: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
struct Claim {
    registered: RegisteredClaim,
    payload: Map<String, Value>
}

