Simple JWT
=============

A rust lib that used to encode/decode json web token. This lib use [serde](https://serde.rs) to ser/deserialize json.
Compiled only using rust nightly....

So it's Experimental, and more function (and document) will be added in future.

Example
===========

```rust
    let mut claim = Claim::default();
    claim.iss("realli");
    claim.payload.insert("key12".to_string(), to_value(12));
    let result = encode(&claim, "secret").unwrap();
    println!("hashed result is {}", result);
    let new_claim = decode(&result, "secret").unwrap();
    assert_eq!(claim, new_claim);
```
