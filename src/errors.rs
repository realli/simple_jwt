use serde_json;
use base64;
use openssl;

error_chain! {
    links {}
    foreign_links {
        JsonError(serde_json::Error);
        Base64Error(base64::DecodeError);
        CryptoFailure(openssl::error::ErrorStack);
    }
    errors {
        UnsupportAlgorithm {
            description("unsupport algorithm")
            display("unsupport algorithm")
        }
        InvalidFormat {
            description("invalid format")
            display("invalid format")
        }
        InvalidSignature {
            description("invalid signature")
            display("invalid signature")
        }
    }
}
