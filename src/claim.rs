use std::default::Default;
use serde::{Serialize};
use serde_json;
use serde_json::value::{Map, Value, to_value};
use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};

use super::errors::{JWTError, Result};
use super::utils::JWTStringConvertable;

#[cfg(feature = "serde_derive")]
include!("claim.in.rs");

#[cfg(feature = "serde_codegen")]
include!(concat!(env!("OUT_DIR"), "/claim.rs"));

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
        self.payload.insert(key.to_string(), to_value(v));
        self
    }

    pub fn get_payload_field(&self, key: &str) -> Option<&Value> {
        self.payload.get(&key.to_string())
    }

}

impl JWTStringConvertable for Claim {
    fn from_base64_str(string: &str) -> Result<Claim> {
        let slice = try!(string.from_base64());
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
        if let Some(ref v) = self.registered.sub {
            map.insert("sub".to_string(), to_value(v));
        };

        let b_string = try!(serde_json::to_vec(&map));
        Ok(b_string.to_base64(URL_SAFE))
    }
}
