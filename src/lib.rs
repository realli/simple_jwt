#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_json;
extern crate rustc_serialize;

mod errors;
mod utils;
mod header;
mod claim;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_can_be_convert_from_and_to_base64() {
        let header = Header::default();
        let b_string = header.to_base64_str().unwrap();
        let new_header = Header::from_base64_str(&b_string).unwrap();
        assert_eq!(header, new_header);
    }

    #[test]
    fn claim_can_be_convert_form_and_to_base64() {
        let claim = Claim::default();
        let b_string = claim.to_base64_str().unwrap();
        println!("bstring is {}",b_string);
        let new_claim = Claim::from_base64_str(&b_string).unwrap();
        assert_eq!(claim, new_claim);
    }
}

pub use self::utils::JWTStringConvertable;
pub use self::header::{Header, Algorithm};
pub use self::claim::{Claim};

