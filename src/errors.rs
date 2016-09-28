use serde_json::error::{Error};
use rustc_serialize::base64::FromBase64Error;
use std::result as std_result;
use std::fmt;
use std::error;
use std::convert::From;
use openssl::error::ErrorStack;

/// all the errors may raised during jwt encode/decode
#[derive(Debug)]
pub enum JWTError {
    JsonError(Error),
    Base64Error(FromBase64Error),
    CryptoFailure(ErrorStack),
    UnsupportAlgorithm,
    InvalidFormat,
    InvalidSignature,
}

impl From<Error> for JWTError {
    fn from(e: Error) -> JWTError {
        JWTError::JsonError(e)
    }
}

impl From<FromBase64Error> for JWTError {
    fn from(e: FromBase64Error) -> JWTError {
        JWTError::Base64Error(e)
    }
}

impl From<ErrorStack> for JWTError {
    fn from(e: ErrorStack) -> JWTError {
        JWTError::CryptoFailure(e)
    }
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
