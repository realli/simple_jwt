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


// some helper function to convert ecdsa signature der from/to raw format
pub fn ecdsa_der_to_raw(s: &[u8]) -> Result<Vec<u8>> {
    if s.len() < 6 {
        return Err(ErrorKind::InvalidSignature.into());
    }
    let mut result = Vec::new();
    if s[0] != 0x30 || s[2] != 0x02 {
        return Err(ErrorKind::InvalidSignature.into());
    }
    let t_len = s[1] as usize;
    if s.len() != 2 + t_len {
        return Err(ErrorKind::InvalidSignature.into());
    }
    let r_len = s[3] as usize;
    if r_len + 2 > t_len {
        return Err(ErrorKind::InvalidSignature.into());
    }

    for i in 4..4+r_len {
        if i == 4 && s[i] == 0x00 {
            continue;
        }
        result.push(s[i]);
    }
    let s_len = s[4 + r_len + 1] as usize;
    if 4 + s_len + 2 + r_len > s.len() {
        return Err(ErrorKind::InvalidSignature.into());
    }
    for i in 6+r_len..6+r_len+s_len {
        if i == 6 + r_len && s[i] == 0x00 {
            continue;
        }
        result.push(s[i]);
    }
    Ok(result)
}

pub fn ecdsa_raw_to_der(s: &[u8]) -> Result<Vec<u8>> {
    if s.len() <= 0 || s.len() % 2 != 0 {
        return Err(ErrorKind::InvalidSignature.into());
    }
    let half_len = s.len() / 2;

    let r_0 = s[0];
    let mut r_append_zero = false;
    let mut r_len = half_len;
    if r_0 > 0x7f {
        r_append_zero = true;
        r_len += 1;
    }
    let s_0 = s[half_len];
    let mut s_append_zero = false;
    let mut s_len = half_len;
    if s_0 > 0x7f {
        s_append_zero = true;
        s_len += 1;
    }

    let mut result = Vec::new();
    result.push(0x30);
    result.push(r_len as u8 + s_len as u8 + 4 );
    result.push(0x02);
    result.push(r_len as u8);
    for i in 0..half_len {
        if i == 0 && r_append_zero {
            result.push(0x00);
        }
        result.push(s[i]);
    }
    result.push(0x02);
    result.push(s_len as u8);

    for i in 0..half_len {
        if i == 0 && s_append_zero {
            result.push(0x00);
        }
        result.push(s[half_len + i]);
    }
    Ok(result)
}
