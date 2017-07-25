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

fn _safe_get_u8s(s: &[u8], i: usize) -> Result<u8> {
    s.get(i).map(|u| u.clone()).ok_or(ErrorKind::InvalidSignature.into())
}

// some helper function to convert ecdsa signature der from/to raw format
pub fn ecdsa_der_to_raw(s: &[u8]) -> Result<Vec<u8>> {
    let mut idx = 0;
    let s0 = _safe_get_u8s(s, idx)?;
    idx += 1;
    if s0 != 0x30 {
        return Err(ErrorKind::InvalidSignature.into());
    }

    let mut result = Vec::new();

    let t_len = _safe_get_u8s(s, idx)? as usize;
    idx += 1;
    if t_len > 127 { // more than one byte for len
        idx += t_len - 128;
    }

    idx += 1; // skip the 0x02

    let mut r_len = _safe_get_u8s(s, idx)? as usize;
    idx += 1;
    if r_len > 127 {
        let bit_len = r_len - 128;
        if bit_len > 4 || bit_len == 0 { // only deal with maximum 4 bytes
            return Err(ErrorKind::InvalidSignature.into());
        }
        r_len = 0x0;
        for _ in 0..bit_len {
            r_len = r_len << 8;
            r_len = r_len | (_safe_get_u8s(s, idx)? as usize);
            idx += 1;
        }
    }

    for i in 0..r_len {
        let target = _safe_get_u8s(s, idx)?;
        idx += 1;
        if i == 0 && target == 0x00 {
            continue;
        }
        result.push(target);
    }

    idx += 1; // skip the 0x02

    let mut s_len = _safe_get_u8s(s, idx)? as usize;
    idx += 1;

    if s_len > 127 {
        let bit_len = s_len - 128;
        if bit_len > 4 || bit_len == 0 { // only deal with maximum 4 bytes
            return Err(ErrorKind::InvalidSignature.into());
        }
        s_len = 0x0;
        for _ in 0..bit_len {
            s_len = s_len << 8;
            s_len = s_len | (_safe_get_u8s(s, idx)? as usize);
            idx += 1;
        }
    }

    for i in 0..s_len {
        let target = _safe_get_u8s(s, idx)?;
        idx += 1;
        if i == 0 && target == 0x00 {
            continue;
        }
        result.push(target);
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

    let mut r_len_byte = 0;
    if r_len > 127 {
        r_len_byte = 1;
        let mut temp = r_len;
        temp = temp >> 8;
        while temp > 0 {
            r_len_byte += 1;
            temp = temp >> 8;
        }
    }

    let mut s_len_byte = 0;
    if s_len > 127 {
        s_len_byte = 1;
        let mut temp = s_len;
        temp = temp >> 8;
        while temp > 0 {
            s_len_byte += 1;
            temp = temp >> 8;
        }
    }

    let t_len = 2 + 2 + r_len_byte + s_len_byte + r_len + s_len;
    let mut t_len_byte = 0;
    if t_len > 127 {
        t_len_byte = 1;
        let mut temp = t_len;
        temp = temp >> 8;
        while temp > 0 {
            t_len_byte += 1;
            temp = temp >> 8;
        }
    }

    let mut result = Vec::new();
    result.push(0x30);
    if t_len > 127 {
        result.push((t_len_byte + 128) as u8);
        while t_len_byte > 0 {
            t_len_byte -= 1;
            result.push((t_len / 2^t_len_byte) as u8);
        }
    } else {
        result.push(t_len as u8);
    }
    result.push(0x02);
    if r_len > 127 {
        result.push((r_len_byte + 128) as u8);
        while r_len_byte > 0 {
            r_len_byte -= 1;
            result.push((r_len / 2^r_len_byte) as u8);
        }
    } else {
        result.push(r_len as u8);
    }

    for i in 0..half_len {
        if i == 0 && r_append_zero {
            result.push(0x00);
        }
        result.push(s[i]);
    }
    result.push(0x02);

    if s_len > 127 {
        result.push((s_len_byte + 128) as u8);
        while s_len_byte > 0 {
            s_len_byte -= 1;
            result.push((s_len / 2^s_len_byte) as u8);
        }
    } else {
        result.push(s_len as u8);
    }

    for i in 0..half_len {
        if i == 0 && s_append_zero {
            result.push(0x00);
        }
        result.push(s[half_len + i]);
    }
    Ok(result)
}
