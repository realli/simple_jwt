(function() {var implementors = {};
implementors["base64"] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='enum' href='base64/enum.Base64Error.html' title='base64::Base64Error'>Base64Error</a>",];
implementors["libc"] = [];
implementors["openssl"] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='struct' href='openssl/error/struct.ErrorStack.html' title='openssl::error::ErrorStack'>ErrorStack</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='struct' href='openssl/error/struct.Error.html' title='openssl::error::Error'>Error</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='enum' href='openssl/ssl/enum.Error.html' title='openssl::ssl::Error'>Error</a>","impl&lt;S:&nbsp;<a class='trait' href='https://doc.rust-lang.org/nightly/core/any/trait.Any.html' title='core::any::Any'>Any</a> + <a class='trait' href='https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html' title='core::fmt::Debug'>Debug</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>StdError</a> for <a class='enum' href='openssl/ssl/enum.HandshakeError.html' title='openssl::ssl::HandshakeError'>HandshakeError</a>&lt;S&gt;","impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='struct' href='openssl/x509/struct.X509VerifyError.html' title='openssl::x509::X509VerifyError'>X509VerifyError</a>",];
implementors["serde"] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='struct' href='serde/de/value/struct.Error.html' title='serde::de::value::Error'>Error</a>",];
implementors["serde_json"] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='struct' href='serde_json/error/struct.Error.html' title='serde_json::error::Error'>Error</a>",];
implementors["simple_jwt"] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/std/error/trait.Error.html' title='std::error::Error'>Error</a> for <a class='enum' href='simple_jwt/enum.JWTError.html' title='simple_jwt::JWTError'>JWTError</a>",];
implementors["syn"] = [];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
