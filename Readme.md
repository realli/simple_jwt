Simple JWT
=============
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
simple_jwt = "0.1.0"
```

Example
===========

```rust
    use simple_jwt::{encode, decode, Claim, Algorithm};
    let mut claim = Claim::default();
    claim.set_iss("some iss");
    claim.set_payload_field("stringhh", 12);
    let result = encode(&claim, "secret", Algorithm::HS256).unwrap();
    println!("hashed result is {}", result);
    let new_claim = decode(&result, "secret").unwrap();
    assert_eq!(claim, new_claim);
```
