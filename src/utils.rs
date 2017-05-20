use std::marker::Sized;
use serde::{Serialize};
use serde::de::DeserializeOwned;
use serde_json;
use base64::{encode_config, decode_config, URL_SAFE};

use super::errors::*;

/// trait that can be convert to/from base64 string
/// impl for `serde::Serialize`+`serde::Deserialize` are already defined
pub trait JWTStringConvertable : Sized{
    fn from_base64_str(string: &str) -> Result<Self>; 
    fn to_base64_str(&self) -> Result<String>;
}

impl<T> JWTStringConvertable for T
    where T: Serialize + DeserializeOwned {
    fn from_base64_str(string: &str) -> Result<T> {
        let slice = try!(decode_config(string, URL_SAFE));
        let result = serde_json::from_slice(&slice)?;
        Ok(result)
    }

    fn to_base64_str(&self) -> Result<String> {
        let b_string = try!(serde_json::to_vec(&self));
        Ok(encode_config(&b_string,URL_SAFE))
    }
}

