#[allow(unused_attributes)]
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaim {
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub prn: Option<String>,
    pub jti: Option<String>,
    pub typ: Option<String>
}

#[allow(unused_attributes)]
#[derive(Debug, Default, PartialEq)]
pub struct Claim {
    pub registered: RegisteredClaim,
    pub payload: Map<String, Value>
}
