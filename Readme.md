Simple JWT
=============

[![](http://meritbadge.herokuapp.com/simple_jwt)](https://crates.io/crates/simple_jwt)

[Documentation](http://realli.github.io/simple_jwt/simple_jwt/)


A very simple crate to deal with [json web token](http://jwt.io), 
this lib use the `rust-openssl`, so you may want to check the
[rust-openssl](https://github.com/sfackler/rust-openssl) to find the
set-up of openssl runtime lib. 

# Support Algirithm
* HS256/384/512
* RS256/384/512
* to be added...

Usage
=======

```
[denpendencies]
simple_jwt = "1.0.0"
```

Example
===========

```rust
    extern crate simple_jwt;
    use simple_jwt::{encode, decode, Claim, Algorithm};

    fn main() {
        let mut claim = Claim::default();
        claim.set_iss("some iss");
        claim.set_payload_field("stringhh", 12);
        let result = encode(&claim, "secret", Algorithm::HS256).unwrap();
        println!("hashed result is {}", result);
        let new_claim = decode(&result, "secret").unwrap();
        assert_eq!(claim, new_claim);
    }

```

Or simple use your custom struct

```rust
    #[macro_use]
    extern crate serde_derive;
    extern crate serde;
    extern crate simple_jwt;

    use serde::{Serialize, Deserialize};
    use simple_jwt::{encode, decode, Claim, Algorithm};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct MyStruct {
        field_u32: u32,
        field_str: String
    }

    fn main() {
        let myStruct = MyStruct {field_str: String::from("hello"), field_u32: 32};

        let result = encode(&myStruct, "secret", Algorithm::HS256).unwrap();
        println!("hashed result is {}", result);
        let newStruct = decode(&result, "secret").unwrap();
        assert_eq!(myStruct, newStruct);
    }
```

