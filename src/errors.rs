use serde_json::error::{Error};
use rustc_serialize::base64::FromBase64Error;
use std::result as std_result;
use std::fmt;
use std::error;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum JWTError {
    JsonError(Error),
    Base64Error(FromBase64Error),
    CryptoFailure(ErrorStack),
    UnsupportAlgorithm,
    InvalidFormat,
    InvalidSignature,
}

impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            JWTError::JsonError(ref err) => write!(f, "Json en/de error: {}", err),
            JWTError::Base64Error(ref err) => write!(f, "Base64 Decode error: {}", err),
            JWTError::CryptoFailure(ref err) => write!(f, "crypto  error: {}", err),
            JWTError::InvalidFormat => write!(f, "Format is invalidate"),
            JWTError::InvalidSignature => write!(f, "signature is invalid!"),
            JWTError::UnsupportAlgorithm => write!(f, "algorithm is not support"),

        }
    }
}

impl error::Error for JWTError {
    fn description(&self) -> &str {
        match *self {
            JWTError::JsonError(ref err) => err.description(),
            JWTError::Base64Error(ref err) => err.description(),
            JWTError::CryptoFailure(ref err) => err.description(),
            JWTError::InvalidFormat => "Format is invalidate",
            JWTError::InvalidSignature => "signature is invalid!",
            JWTError::UnsupportAlgorithm => "algorithm is not support",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self{
            JWTError::JsonError(ref err) => Some(err),
            JWTError::Base64Error(ref err) => Some(err),
            JWTError::CryptoFailure(ref err) => Some(err),
            _ => None
        }
    }
}

pub type Result<T> = std_result::Result<T, JWTError>;
