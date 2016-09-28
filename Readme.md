Simple JWT
=============

A rust lib that used to encode/decode json web token. This lib use [serde](https://serde.rs) to ser/deserialize json.
Compiled only using rust nightly....

So it's Experimental, and more function (and document) will be added in future.

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
