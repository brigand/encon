<!-- {\{badges}} -->

# encon

Encon is an optionally-encrypted config format, built on top of JSON. A mix of encrypted
and plain fields, and support for encrypting arbitrary JSON values make it very flexible.

## Example
```rust
use serde_json::json;
use encon::{Password, Map, Encryptable};

let pass = Password::new("strongpassword");

let mut map = Map::new();
map.insert("foo", Encryptable::Plain("Foo".into()));
map.insert("bar", Encryptable::Plain("Bar".into()));
map.get_mut(&"foo".to_owned()).unwrap().intend_encrypted();

assert_eq!(map.get(&"foo".to_owned()).unwrap().is_encrypted(), false);
assert_eq!(map.get(&"bar".to_owned()).unwrap().is_encrypted(), false);

map.apply_all_intents(&pass).unwrap();
assert_eq!(map.get(&"foo".to_owned()).unwrap().is_encrypted(), true);
assert_eq!(map.get(&"bar".to_owned()).unwrap().is_encrypted(), false);

let json = map.to_json_pretty().unwrap();
let mut map2: Map = serde_json::from_str(&json).unwrap();
assert_eq!(map2.get(&"foo".to_owned()).unwrap().is_encrypted(), true);
assert_eq!(map2.get(&"bar".to_owned()).unwrap().is_encrypted(), false);

let value = map2.get_mut(&"foo".to_owned()).unwrap()
    .to_decrypted(&pass).unwrap()
    .as_plain().unwrap().clone();
assert_eq!(value, json!("Foo"));
```

Current version: 0.0.1

## Other Crates

- `encon-cli`: a command line tool for interacting with encon JSON files
- `encon-js`: an npm package (`npm install encon`)

All crates licensed as MIT
