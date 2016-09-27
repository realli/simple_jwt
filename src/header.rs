use std::default::Default;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: String
}

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

