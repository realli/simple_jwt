use std::default::Default;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: String
}

impl Default for Header {
    fn default() -> Header {
        Header {alg: Algorithm::HS256, typ: "JWT".to_string()}
    }
}

impl Header {
    pub fn new(alg: Algorithm) -> Header {
        Header {alg: alg, typ: "JWT".to_string()}
    }
}

