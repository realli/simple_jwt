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