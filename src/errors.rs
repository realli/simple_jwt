use serde_json::error::{Error};
use rustc_serialize::base64::FromBase64Error;
use std::result as std_result;
use std::fmt;
use std::error;

#[derive(Debug)]
pub enum JWTError {
    JsonError(Error),
    Base64Error(FromBase64Error),
    BadJsonFormat,
}

impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            JWTError::JsonError(ref err) => write!(f, "Json en/de error: {}", err),
            JWTError::Base64Error(ref err) => write!(f, "Base64 Decode error: {}", err),
            JWTError::BadJsonFormat => write!(f, "Json is not a object"),
        }
    }
}

impl error::Error for JWTError {
    fn description(&self) -> &str {
        match *self {
            JWTError::JsonError(ref err) => err.description(),
            JWTError::Base64Error(ref err) => err.description(),
            JWTError::BadJsonFormat => "Bad Json Format for Registered Fields",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self{
            JWTError::JsonError(ref err) => Some(err),
            JWTError::Base64Error(ref err) => Some(err),
            JWTError::BadJsonFormat => None
        }
    }
}

pub type Result<T> = std_result::Result<T, JWTError>;
