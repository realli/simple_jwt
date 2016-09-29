#[allow(unused_attributes)]
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaim {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub aud: Option<String>,
    pub jti: Option<String>,
}

#[allow(unused_attributes)]
#[derive(Debug, Default, PartialEq)]
pub struct Claim {
    pub registered: RegisteredClaim,
    pub payload: Map<String, Value>
}
