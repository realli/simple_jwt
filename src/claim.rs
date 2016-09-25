use std::default::Default;
use serde_json;
use serde_json::value::{Map, Value, to_value};
use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};

use super::errors::{JWTError, Result};
use super::utils::JWTStringConvertable;

#[allow(unused_attributes)]
#[derive(Debug, Display, Default, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Display, Default, PartialEq)]
pub struct Claim {
    registered: RegisteredClaim,
    pub payload: Map<String, Value>
}

impl Claim {
    pub fn exp(&mut self, v: u64) -> &mut Claim {
        self.registered.exp = Some(v);
        self
    }
    pub fn nbf(&mut self, v: u64) -> &mut Claim {
        self.registered.nbf = Some(v);
        self
    }
    pub fn iat(&mut self, v: u64) -> &mut Claim {
        self.registered.iat = Some(v);
        self
    }
    pub fn iss(&mut self, v: &str) -> &mut Claim {
        self.registered.iss = Some(v.to_string());
        self
    }
    pub fn aud(&mut self, v: &str) -> &mut Claim {
        self.registered.aud = Some(v.to_string());
        self
    }
    pub fn prn(&mut self, v: &str) -> &mut Claim {
        self.registered.prn = Some(v.to_string());
        self
    }
    pub fn jti(&mut self, v: &str) -> &mut Claim {
        self.registered.jti = Some(v.to_string());
        self
    }
    pub fn typ(&mut self, v: &str) -> &mut Claim {
        self.registered.typ = Some(v.to_string());
        self
    }
}

impl JWTStringConvertable for Claim {
    fn from_base64_str(string: &str) -> Result<Claim> {
        let slice = try!(string.from_base64().map_err(JWTError::Base64Error));
        let obj: Value = try!(serde_json::from_slice(&slice).map_err(JWTError::JsonError));
        let mut map = match obj {
            Value::Object(map) => map,
            _ => return Err(JWTError::InvalidFormat)
        };
        // dispatch every items to 
        let mut claim = Claim::default();
        {
            let reg: &mut RegisteredClaim = &mut claim.registered;
            reg.exp = match map.remove("exp") {
                Some(Value::U64(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.nbf = match map.remove("nbf") {
                Some(Value::U64(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.iat = match map.remove("iat") {
                Some(Value::U64(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.iss = match map.remove("iss") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.aud = match map.remove("aud") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.prn = match map.remove("prn") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.jti = match map.remove("jti") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.typ = match map.remove("typ") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
        }
        claim.payload = map;
        Ok(claim)
    }

    fn to_base64_str(&self) -> Result<String> {
        let mut map: Map<String, Value> = self.payload.clone();
        if let Some(v) = self.registered.exp {
            map.insert("exp".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.nbf {
            map.insert("nbf".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.iat {
            map.insert("iat".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.iss {
            map.insert("iss".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.aud {
            map.insert("aud".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.prn {
            map.insert("prn".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.jti {
            map.insert("jti".to_string(), to_value(v));
        };
        if let Some(ref v) = self.registered.typ {
            map.insert("typ".to_string(), to_value(v));
        };

        let b_string = try!(serde_json::to_vec(&map).map_err(JWTError::JsonError));
        Ok(b_string.to_base64(URL_SAFE))
    }
}
