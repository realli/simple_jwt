use std::default::Default;

#[cfg(feature = "serde_derive")]
include!("header.in.rs");

#[cfg(feature = "serde_codegen")]
include!(concat!(env!("OUT_DIR"), "/header.rs"));

impl Default for Algorithm {
    fn default() -> Algorithm {
        Algorithm::HS256
    }
}

impl Header {
    pub fn new(alg: Algorithm) -> Header {
        Header {alg: alg, typ: "JWT".to_string()}
    }
}

