Simple JWT
=============

[![](http://meritbadge.herokuapp.com/simple_jwt)](https://crates.io/crates/simple_jwt)

[Documentation](https://realli.github.io/simple_jwt/simple_jwt/)


A very simple crate to deal with [json web token](http://jwt.io), 
this lib use the `rust-openssl`, so you may want to check the
[rust-openssl](https://github.com/sfackler/rust-openssl) to find the
set-up of openssl runtime lib. 

# Support Algirithm
* HS256/384/512
* RS256/384/512
* ES256/384/512

Usage
=======

```
[denpendencies]
simple_jwt = "1.1.0"
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

        // RS256 example
        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCx5gqY8ZZK5MNFHI5V1OYkNXI7
qFka5lHJcUFq6SaZqAXYteKcR4kugITcoILZIpVhM3yOp0octAackM2AOCGfo5Fo
E/W/iSrd8euMy4UkdtD6XfGYkkfO4yfhXpZjyvprhZ027p2X0l7eoRY3KycPYVF1
gC3TfsCAVObIW0MuBQIDAQAB
-----END PUBLIC KEY-----";
        let private_key_pem = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCx5gqY8ZZK5MNFHI5V1OYkNXI7qFka5lHJcUFq6SaZqAXYteKc
R4kugITcoILZIpVhM3yOp0octAackM2AOCGfo5FoE/W/iSrd8euMy4UkdtD6XfGY
kkfO4yfhXpZjyvprhZ027p2X0l7eoRY3KycPYVF1gC3TfsCAVObIW0MuBQIDAQAB
AoGAVO7oVlbZE06er8tPZUksy1K9BCB+0inuGEe7HMjNhgTDLdDArS42H356cD8t
2W76dJq5N/5EkumcUnmLs1CZNCt+xSVBL2ihS6LQm5k69vLqGlYMnKMRqAuQMr2C
61/nPgFEaqjjjVyI6yYLMcU2eG2NPoNPBJkjC9yERGlFta0CQQDYlzXtVVTKvhZB
Y4m8UD1GcLFz3cxOPHfs1DzgxxqcME7LeyQHhFkEiqKiUeDEccCMJ4oq9AKqUPvf
MgyAnKm/AkEA0kSOEJ1qwOgLcStmHh4Q9T7zPdnhsDacvBY2EHA248YYgEjOmUFd
5OQmiN9rtiB78E4wSNWSvsG8edQcjvWxOwJAQwrbOHGXY4JfZTIoak/0B5/Obe0T
1ovFG1u+1F0NEZeqbDXbuy/uVgeLu+7YQjZrwXZjwFPzl0CmFjppwE2+BQJBALbI
56Kj5Whaj4/KhVQLGPzIw1TyMhIn92o9+LOjiOPKkgP6xrZNL51JhAIaDp1dccA9
iBXYq19uNTTG4iiYhn8CQG9KpMDscoqocTeBE78jA6pX6ZH0Ppu7me5sds0UtwuS
p5HP/xmDtWJQv5hScT2aWKjjl2kC8eZOHTGgQvjrSm8=
-----END RSA PRIVATE KEY-----";

        let result = encode(&myStruct, private_key_pem, Algorithm::RS256).unwrap();
        let newStruct = decode(&result, public_key_pem).unwrap();
        assert_eq!(myStruct, newStruct);
    }
```

The test in `lib.rs` contains more example
