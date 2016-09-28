#[allow(unused_attributes)]
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct RegisteredClaim {
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    iss: Option<String>,
    aud: Option<String>,
    prn: Option<String>,
    jti: Option<String>,
    typ: Option<String>
}

#[allow(unused_attributes)]
#[derive(Debug, Default, PartialEq)]
pub struct Claim {
    registered: RegisteredClaim,
    pub payload: Map<String, Value>
}