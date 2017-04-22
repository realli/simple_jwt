use std::default::Default;
use serde::{Serialize};
use serde_json;
use serde_json::value::{Map, Value, to_value};
use base64::{encode_config, decode_config, URL_SAFE};

use super::errors::{JWTError, Result};
use super::utils::JWTStringConvertable;

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

/// # JWT Claim
/// some util function to set/get fields
///
/// # Example
/// ```
/// use simple_jwt::Claim;
/// let mut claim = Claim::default();
/// claim.set_iss("some iss");
/// claim.set_payload_field("sub", "some sub");
///
/// println!("{:?}", claim.registered.iss);
/// println!("{:?}", claim.get_payload_field("sub"));
///
/// // payload is acctually a BTreeMap<String, serde_json::Value>
/// println!("{:?}", claim.payload.get("sub"))
/// ```

impl Claim {
    pub fn set_exp(&mut self, v: u64) -> &mut Claim {
        self.registered.exp = Some(v);
        self
    }
    pub fn set_nbf(&mut self, v: u64) -> &mut Claim {
        self.registered.nbf = Some(v);
        self
    }
    pub fn set_iat(&mut self, v: u64) -> &mut Claim {
        self.registered.iat = Some(v);
        self
    }
    pub fn set_iss(&mut self, v: &str) -> &mut Claim {
        self.registered.iss = Some(v.to_string());
        self
    }
    pub fn set_aud(&mut self, v: &str) -> &mut Claim {
        self.registered.aud = Some(v.to_string());
        self
    }
    pub fn set_sub(&mut self, v: &str) -> &mut Claim {
        self.registered.sub = Some(v.to_string());
        self
    }
    pub fn set_jti(&mut self, v: &str) -> &mut Claim {
        self.registered.jti = Some(v.to_string());
        self
    }

    pub fn set_payload_field<V: Serialize>(&mut self, key: &str, v: V) -> &mut Claim{
        self.payload.insert(key.to_string(), to_value(v).unwrap());
        self
    }

    pub fn get_payload_field(&self, key: &str) -> Option<&Value> {
        self.payload.get(&key.to_string())
    }

}

impl JWTStringConvertable for Claim {
    fn from_base64_str(string: &str) -> Result<Claim> {
        let slice = try!(decode_config(string, URL_SAFE));
        let obj: Value = try!(serde_json::from_slice(&slice));
        let mut map = match obj {
            Value::Object(map) => map,
            _ => return Err(JWTError::InvalidFormat)
        };
        // dispatch every items to 
        let mut claim = Claim::default();
        {
            let reg: &mut RegisteredClaim = &mut claim.registered;
            reg.exp = match map.remove("exp") {
                Some(Value::Number(u)) => u.as_u64(),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.nbf = match map.remove("nbf") {
                Some(Value::Number(u)) => u.as_u64(),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::InvalidFormat),
            };
            reg.iat = match map.remove("iat") {
                Some(Value::Number(u)) => u.as_u64(),
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
            reg.sub = match map.remove("sub") {
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
        }
        claim.payload = map;
        Ok(claim)
    }

    fn to_base64_str(&self) -> Result<String> {
        let mut map: Map<String, Value> = self.payload.clone();
        if let Some(v) = self.registered.exp {
            let value = try!(to_value(v));
            map.insert("exp".to_string(), value);
        };
        if let Some(ref v) = self.registered.nbf {
            let value = try!(to_value(v));
            map.insert("nbf".to_string(), value);
        };
        if let Some(ref v) = self.registered.iat {
            let value = try!(to_value(v));
            map.insert("iat".to_string(), value);
        };
        if let Some(ref v) = self.registered.iss {
            let value = try!(to_value(v));
            map.insert("iss".to_string(), value);
        };
        if let Some(ref v) = self.registered.aud {
            let value = try!(to_value(v));
            map.insert("aud".to_string(), value);
        };
        if let Some(ref v) = self.registered.sub {
            let value = try!(to_value(v));
            map.insert("sub".to_string(), value);
        };

        let b_string = try!(serde_json::to_vec(&map));
        Ok(encode_config(&b_string, URL_SAFE))
    }
}

