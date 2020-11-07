<!-- {\{badges}} -->

# encon

Encon is an optionally-encrypted config format, built on top of JSON. A mix of encrypted
and plain fields, and support for encrypting arbitrary JSON values make it very flexible.

## Example
```rust
use encon::Map;
use encon::Password;
use serde_json::json;
use serde_json::from_value;

let pass = Password::new("strongpassword");
let mut map: Map = from_value(json!({
   "k1": "foo",
   "k2": {
       "_encrypted": [
           "c10a4bed22a6511e0b6724f8c62832a6d85c154272b3b57a355568bb6af62ca99cc98e",
           "226163081382e58b796fc212e5427546aa9efb2923f561bc7e3b2418ec9166ea69309d",
           "aa0fee467e6ca538d9f7c29e"
        ]
    }
})).unwrap();

// Decrypt all keys, but remember that k1 is intended to be decrypted (plain text), and k2
// should be encrypted.
map.decrypt_all_in_place(&pass).unwrap();

let v2 = map.get("k2").unwrap().as_plain().unwrap().as_str().unwrap();
assert_eq!(v2, "bar");

// Reapply the intents, since we decrypted the `Map` earlier.
map.apply_all_intents(&pass).unwrap();
assert_eq!(map.get("k1").unwrap().is_encrypted(), false);
assert_eq!(map.get("k2").unwrap().is_encrypted(), true);

// Change the intent of one of the fields.
map.get_mut("k1").unwrap().intend_encrypted();

// Still not encrypted
assert_eq!(map.get("k1").unwrap().is_encrypted(), false);
map.apply_all_intents(&pass).unwrap();

// *Now* it's encrypted (and likewise encrypted fields with decrypted intent would
// be decrypted by the above).
assert_eq!(map.get("k1").unwrap().is_encrypted(), true);

// When converted back to JSON we see that "k1" is now encrypted.
// Note: we can only call this when all intents match reality, which the `apply_all_intents`
// call above ensures.
let json = map.to_json_compact().unwrap();
let expected = r#"{"k1":{"_encrypted":["#;
assert_eq!(&json[..expected.len()], expected);
```

Current version: 0.0.3

## Other Crates

- `encon-cli`: a command line tool for interacting with encon JSON files
- `encon-js`: an npm package (`npm install encon`)

All code licensed as MIT
