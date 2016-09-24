use std::default::Default;
use serde::{Serialize, Deserialize};
use serde_json;
use rustc_serialize::base64::{Config, FromBase64, ToBase64, URL_SAFE};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    alg: Algorithm,
    typ: String
}

impl Default for Header {
    fn default() -> Header {
        Header {alg: Algorithm::HS256, typ: "JWT".to_string()}
    }
}

impl ToBase64 for Header {
    fn to_base64(&self, config: Config) -> String {
        let b_string = serde_json::to_vec(&self).unwrap();
        b_string.to_base64(config)
    }
}

impl Header {
    pub fn new(alg: Algorithm) -> Header {
        Header {alg: alg, typ: "JWT".to_string()}
    }

    pub fn from_base64_str(string: &str) -> Header {
        let slice = string.from_base64().unwrap();
        serde_json::from_slice(&slice).unwrap()
    }

    pub fn to_base64_str(&self) -> String {
        self.to_base64(URL_SAFE)
    }
}

