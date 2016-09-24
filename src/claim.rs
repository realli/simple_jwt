use std::default::Default;
use std::collections::btree_map::BTreeMap;
use serde_json;
use serde_json::value::{Map, Value, to_value};
use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};

use super::errors::{JWTError, Result};
use super::utils::JWTStringConvertable;

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

#[derive(Debug, Display, Default, PartialEq)]
pub struct Claim {
    registered: RegisteredClaim,
    payload: Map<String, Value>
}

impl JWTStringConvertable for Claim {
    fn from_base64_str(string: &str) -> Result<Claim> {
        let slice = try!(string.from_base64().map_err(JWTError::Base64Error));
        let obj: Value = try!(serde_json::from_slice(&slice).map_err(JWTError::JsonError));
        let mut map = match obj {
            Value::Object(map) => map,
            _ => return Err(JWTError::BadJsonFormat)
        };
        // dispatch every items to 
        let mut claim = Claim::default();
        {
            let reg: &mut RegisteredClaim = &mut claim.registered;
            reg.exp = match map.remove("exp") {
                Some(Value::U64(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.nbf = match map.remove("nbf") {
                Some(Value::U64(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.iat = match map.remove("iat") {
                Some(Value::U64(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.iss = match map.remove("iss") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.aud = match map.remove("aud") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.prn = match map.remove("prn") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.jti = match map.remove("jti") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
            reg.typ = match map.remove("typ") {
                Some(Value::String(u)) => Some(u),
                Some(Value::Null) => None,
                None => None,
                _ => return Err(JWTError::BadJsonFormat),
            };
        }
        Ok(claim)
    }

    fn to_base64_str(&self) -> Result<String> {
        let mut map: Map<String, Value> = BTreeMap::new();
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
