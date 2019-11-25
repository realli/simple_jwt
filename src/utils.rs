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
        let slice = decode_config(string, URL_SAFE)?;
        let result = serde_json::from_slice(&slice)?;
        Ok(result)
    }

    fn to_base64_str(&self) -> Result<String> {
        let b_string = serde_json::to_vec(&self)?;
        Ok(encode_config(&b_string,URL_SAFE))
    }
}

fn _safe_get_u8s(s: &[u8], i: usize) -> Result<u8> {
    s.get(i).map(|u| u.clone()).ok_or(ErrorKind::InvalidSignature.into())
}


pub const P256_ORDER_LEN: usize = 32;
pub const P384_ORDER_LEN: usize = 48;
pub const P521_ORDER_LEN: usize = 66;
// some helper function to convert ecdsa signature der from/to raw format
pub fn ecdsa_der_to_raw(s: &[u8], order_len: usize) -> Result<Vec<u8>> {
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

    if r_len > order_len + 1 {
        return Err(ErrorKind::InvalidSignature.into());
    } else if r_len == order_len + 1 {
        let _temp = _safe_get_u8s(s, idx)?;
        idx += 1;
        r_len = order_len;
        if _temp != 0x0 {
            return Err(ErrorKind::InvalidSignature.into());
        }
    }

    for i in 0..r_len {
        if i == 0 && order_len > r_len {
            for _ in 0..order_len-r_len {
                result.push(0x0);
            }
        }
        let target = _safe_get_u8s(s, idx)?;
        idx += 1;
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

    if s_len > order_len + 1 {
        return Err(ErrorKind::InvalidSignature.into());
    } else if s_len == order_len + 1 {
        let _temp = _safe_get_u8s(s, idx)?;
        idx += 1;
        s_len = order_len;
        if _temp != 0x0 {
            return Err(ErrorKind::InvalidSignature.into());
        }
    }

    for i in 0..s_len {
        if i == 0 && order_len > s_len {
            for _ in 0..order_len-s_len {
                result.push(0x0);
            }
        }
        let target = _safe_get_u8s(s, idx)?;
        idx += 1;
        result.push(target);
    }

    Ok(result)
}

pub fn ecdsa_raw_to_der(s: &[u8], order_len: usize) -> Result<Vec<u8>> {
    if s.len() != order_len * 2 {
        return Err(ErrorKind::InvalidSignature.into());
    }
    let rs = &s[0..order_len];
    let ss = &s[order_len..s.len()];
    let mut idx = 0;
    while idx < rs.len() && rs[idx] == 0x0 {
        idx += 1;
    }
    let rs = &rs[idx..rs.len()];

    idx = 0;
    while idx < ss.len() && ss[idx] == 0x0 {
        idx += 1;
    }
    let ss = &ss[idx..ss.len()];

    _ecdsa_raw_to_der(rs, ss)
}

fn _ecdsa_raw_to_der(rs: &[u8], ss: &[u8]) -> Result<Vec<u8>> {
    let r_0 = rs[0];
    let mut r_append_zero = false;
    let mut r_len = rs.len();
    if r_0 > 0x7f {
        r_append_zero = true;
        r_len += 1;
    }
    let s_0 = ss[0];
    let mut s_append_zero = false;
    let mut s_len = ss.len();
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
            result.push((t_len / (2 as usize).pow(t_len_byte)) as u8);
        }
    } else {
        result.push(t_len as u8);
    }

    result.push(0x02);
    if r_len > 127 {
        result.push((r_len_byte + 128) as u8);
        while r_len_byte > 0 {
            r_len_byte -= 1;
            result.push((r_len / (2 as usize).pow(r_len_byte as u32)) as u8);
        }
    } else {
        result.push(r_len as u8);
    }

    for i in 0..rs.len() {
        if i == 0 && r_append_zero {
            result.push(0x00);
        }
        result.push(rs[i]);
    }
    result.push(0x02);

    if s_len > 127 {
        result.push((s_len_byte + 128) as u8);
        while s_len_byte > 0 {
            s_len_byte -= 1;
            result.push((s_len / (2 as usize).pow(s_len_byte as u32)) as u8);
        }
    } else {
        result.push(s_len as u8);
    }

    for i in 0..ss.len() {
        if i == 0 && s_append_zero {
            result.push(0x00);
        }
        result.push(ss[i]);
    }
    Ok(result)
}
