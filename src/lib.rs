//! Encon is an optionally-encrypted config format, built on top of JSON. A mix of encrypted
//! and plain fields, and support for encrypting arbitrary JSON values make it very flexible.
//!
//! # Example
//! ```
//! use serde_json::json;
//! use encon::{Password, Map, Encryptable};
//!
//! let pass = Password::new("strongpassword");
//!
//! let mut map = Map::new();
//! map.insert("foo", Encryptable::Plain("Foo".into()));
//! map.insert("bar", Encryptable::Plain("Bar".into()));
//! map.get_mut(&"foo".to_owned()).unwrap().intend_encrypted();
//!
//! assert_eq!(map.get(&"foo".to_owned()).unwrap().is_encrypted(), false);
//! assert_eq!(map.get(&"bar".to_owned()).unwrap().is_encrypted(), false);
//!
//! map.apply_all_intents(&pass).unwrap();
//! assert_eq!(map.get(&"foo".to_owned()).unwrap().is_encrypted(), true);
//! assert_eq!(map.get(&"bar".to_owned()).unwrap().is_encrypted(), false);
//!
//! let json = map.to_json_pretty().unwrap();
//! let mut map2: Map = serde_json::from_str(&json).unwrap();
//! assert_eq!(map2.get(&"foo".to_owned()).unwrap().is_encrypted(), true);
//! assert_eq!(map2.get(&"bar".to_owned()).unwrap().is_encrypted(), false);
//!
//! let value = map2.get_mut(&"foo".to_owned()).unwrap()
//!     .to_decrypted(&pass).unwrap()
//!     .as_plain().unwrap().clone();
//! assert_eq!(value, json!("Foo"));
//! ```
mod error;
pub mod legacy;
/// Serialize/Deserialize impls are in here
mod serde;
mod util;

pub use error::{DecryptError, EnconError, EncryptError, MapToJsonError};
use indexmap::map::IndexMap;
use serde_json::Value;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf as aead;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::randombytes::randombytes;
use std::fmt;
use std::io::Write as _;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

pub const SIGNATURE: [u8; 4] = [0xC2, 0x0A, 0x4B, 0xED];

/// `init()` initializes the sodium library and chooses faster versions of the primitives
/// if possible. init() also makes the random number generation functions thread-safe
///
/// See also [`sodiumoxide::init`].
///
/// [`sodiumoxide::init`]: https://docs.rs/sodiumoxide/0.2/sodiumoxide/fn.init.html
pub fn init() -> Result<(), ()> {
    sodiumoxide::init()
}

/// Represents an encryption password, and contains the low level encrypt/decrypt operations
/// on lists of bytes.
///
/// The encryption used is [ChaCha20/Poly1305] (an Authenticated Encryption with Associated
/// Data algorithm) of [libsodium's secret-stream].
///
/// [ChaCha20/Poly1305]: https://tools.ietf.org/html/rfc7905
/// [sodium's secret-stream]: https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/secretstream/index.html
#[derive(Clone)]
pub struct Password {
    password: Arc<String>,
}

impl Password {
    /// Create a new password for encryption and decryption.
    pub fn new(password: impl Into<String>) -> Self {
        Password {
            password: Arc::new(password.into()),
        }
    }

    /// Encrypt a byte slice with this password.
    ///
    /// # Example
    ///
    /// Note that encrypting the same data twice will give different bytes as output.
    ///
    /// ```
    /// use encon::Password;
    ///
    /// let pw = Password::new("strongpassword");
    /// let data = [0x01, 0x02, 0x03];
    /// let first: Vec<u8> = pw.encrypt(data).unwrap();
    /// let second: Vec<u8> = pw.encrypt(data).unwrap();
    /// assert_ne!(first, second);
    /// ```
    pub fn encrypt(&self, bytes: impl AsRef<[u8]>) -> Result<Vec<u8>, EncryptError> {
        let bytes = bytes.as_ref();

        let mut output = Vec::default();

        // write file signature
        output.write_all(&SIGNATURE).map_err(EncryptError::write)?;

        let salt = pwhash::gen_salt();
        output.write_all(&salt.0).map_err(EncryptError::write)?;

        let mut key = [0u8; aead::KEYBYTES];
        pwhash::derive_key_interactive(&mut key, self.password.as_bytes(), &salt).unwrap();

        let key = aead::Key(key);

        let nonce_bytes = randombytes(aead::NONCEBYTES);
        let nonce = aead::Nonce::from_slice(&nonce_bytes).expect("Nonce::from_slice");

        output
            .write_all(&nonce_bytes)
            .map_err(EncryptError::write)?;

        let sealed = aead::seal(bytes, None, &nonce, &key);

        output.write_all(&sealed).map_err(EncryptError::write)?;

        Ok(output)
    }

    /// Decrypt a byte slice with this password.
    ///
    /// # Example
    /// Here is a known working example.
    ///
    /// ```
    /// use encon::Password;
    ///
    /// let password = Password::new("strongpassword");
    /// let buffer = password.decrypt(vec![
    ///     0xc2, 0x0a, 0x4b, 0xed, 0x94, 0xb3, 0x10, 0xf3, 0x8e, 0x97, 0x5e, 0x9a,
    ///     0x9c, 0xb4, 0xf1, 0xd9, 0x4c, 0x32, 0xd4, 0x55, 0x60, 0x92, 0xa4, 0x40,
    ///     0x35, 0x0f, 0x21, 0x51, 0xee, 0x1b, 0x2b, 0xa2, 0x8b, 0x91, 0xdc, 0xe1,
    ///     0xc2, 0xf6, 0x47, 0x3e, 0x07, 0x1f, 0xad, 0xd2, 0x48, 0x14, 0x52, 0x85,
    ///     0xab, 0x4e, 0xa7, 0x5d, 0xee, 0xf5, 0x03, 0xb6, 0x9d, 0xcd, 0xe0, 0xe2,
    ///     0x91, 0x95, 0x49, 0x72, 0x04, 0xed, 0xb9, 0xa4, 0x9f, 0x07, 0x0b, 0x22,
    ///     0x26, 0x51, 0x62, 0x36, 0x52,
    /// ]).unwrap();
    ///
    /// let s = String::from_utf8(buffer).unwrap();
    /// assert_eq!(&s, "Hello, world!");
    /// #
    /// # // Extra round-trip test
    /// # let buffer = password.encrypt("Hello, world!").unwrap();
    /// # let buffer = password.decrypt(buffer).unwrap();
    /// # let s = String::from_utf8(buffer).unwrap();
    /// # assert_eq!(&s, "Hello, world!");
    /// ```
    pub fn decrypt(&self, bytes: impl AsRef<[u8]>) -> Result<Vec<u8>, DecryptError> {
        let bytes = bytes.as_ref();
        if bytes.len() <= (pwhash::SALTBYTES + aead::NONCEBYTES + SIGNATURE.len()) {
            return Err(DecryptError::InputTooShort);
        }

        let mut offset = 0;

        let mut salt = [0u8; pwhash::SALTBYTES];
        let mut signature = [0u8; 4];

        signature.copy_from_slice(&bytes[offset..offset + SIGNATURE.len()]);
        offset += signature.len();

        // TEMP: allows decrypting legacy payloads
        if signature == legacy::SIGNATURE {
            let legacy = legacy::Password::from(self.clone());
            return legacy.decrypt(bytes);
        }

        salt.copy_from_slice(&bytes[offset..offset + pwhash::SALTBYTES]);
        offset += salt.len();

        let salt = pwhash::Salt(salt);

        let mut nonce = [0u8; aead::NONCEBYTES];

        nonce.copy_from_slice(&bytes[offset..offset + aead::NONCEBYTES]);
        offset += nonce.len();
        let nonce = aead::Nonce(nonce);

        let mut key = [0u8; aead::KEYBYTES];
        pwhash::derive_key_interactive(&mut key, self.password.as_bytes(), &salt)
            .map_err(|_| DecryptError::DeriveKey)?;
        let key = aead::Key(key);

        let output = aead::open(&bytes[offset..], None, &nonce, &key)
            .map_err(|_| DecryptError::LikelyWrongPassword)?;

        Ok(output)
    }
}

/// Pairs with `Encryptable`, and is used in `WithIntent`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EncryptableKind {
    Encrypted,
    Plain,
}

impl fmt::Display for EncryptableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Encrypted => "Encrypted",
                Self::Plain => "Plain",
            }
        )
    }
}

/// A value that can either be encrypted or plain, functionality to transition between
/// the two states, and a pretty serde representation. In either variant, it represents an
/// arbitrary JSON value.
///
/// # Example
/// The serialized form of `Encryptable::Plain` is transparent (equivalent to the underlying
/// `serde_json::Value`). The encrypted form uses an array of fixed width hex strings to keep
/// lines short and nicely formatted, even if the encrypted blob is kilobytes in size.
///
/// ```
/// use encon::Encryptable;
/// use serde_json::to_string_pretty;
///
/// let encrypted = Encryptable::Encrypted((0..255).collect());
/// let json = to_string_pretty(&encrypted).unwrap();
/// assert_eq!(json.as_str(), r#"{
///   "_encrypted": [
///     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
///     "232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445",
///     "464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768",
///     "696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b",
///     "8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadae",
///     "afb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1",
///     "d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4",
///     "f5f6f7f8f9fafbfcfdfe"
///   ]
/// }"#);
/// ```
#[derive(Debug, Clone)]
pub enum Encryptable {
    Encrypted(Vec<u8>),
    Plain(Value),
}

impl Encryptable {
    /// Returns the variant kind.
    pub fn kind(&self) -> EncryptableKind {
        match self {
            Self::Encrypted(_) => EncryptableKind::Encrypted,
            Self::Plain(_) => EncryptableKind::Plain,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        match self {
            Self::Encrypted(_) => true,
            _ => false,
        }
    }

    /// If this is the encrypted variant, returns a the encrypted blob.
    pub fn as_encrypted(&self) -> Option<&[u8]> {
        match self {
            Self::Encrypted(value) => Some(&*value),
            _ => None,
        }
    }

    /// If this is the plain variant, returns the serde_json `Value`.
    pub fn as_plain(&self) -> Option<&Value> {
        match self {
            Self::Plain(value) => Some(value),
            _ => None,
        }
    }

    /// If not already encrypted, this will return an encrypted copy of the `Encryptable`.
    ///
    /// See [`Password::encrypt`] for details.
    ///
    /// [`Password::encrypt`]: ./struct.Password.html#method.encrypt
    pub fn to_encrypted(&self, password: &Password) -> Result<Self, EncryptError> {
        Ok(Self::Encrypted(self.encrypt(password)?))
    }

    /// If not already in the plain variant, this will return a decrypted/plain copy of
    /// the `Encryptable`. Will return an error if the password is invalid, or the encrypted
    /// blob is invalid.
    ///
    /// See [`Password::decrypt`] for details.
    ///
    /// [`Password::decrypt`]: ./struct.Password.html#method.decrypt
    pub fn to_decrypted(&self, password: &Password) -> Result<Self, DecryptError> {
        Ok(Self::Plain(self.decrypt(password)?))
    }

    /// Produces the encryption output as a `Vec` of bytes. This encrypts the value if not
    /// already encrypted.
    ///
    /// See [`Password::encrypt`] for details.
    ///
    /// [`Password::encrypt`]: ./struct.Password.html#method.encrypt
    pub fn encrypt(&self, password: &Password) -> Result<Vec<u8>, EncryptError> {
        match self {
            Self::Encrypted(bytes) => Ok(bytes.clone()),
            Self::Plain(value) => {
                let json = serde_json::to_string(value).map_err(EncryptError::serialize)?;
                let bytes = password.encrypt(&json)?;

                Ok(bytes)
            }
        }
    }

    /// Produces the decrypted JSON value. This decrypts the value if
    /// already encrypted.
    ///
    /// See [`Password::decrypt`] for details.
    ///
    /// [`Password::decrypt`]: ./struct.Password.html#method.decrypt
    pub fn decrypt(&self, password: &Password) -> Result<Value, DecryptError> {
        match self {
            Self::Plain(inner) => Ok(inner.clone()),
            Self::Encrypted(bytes) => {
                let bytes = password.decrypt(bytes)?;
                let json = String::from_utf8(bytes).map_err(DecryptError::utf8)?;
                let value: Value =
                    serde_json::from_str(&json).map_err(DecryptError::deserialize)?;

                Ok(value)
            }
        }
    }

    /// Wrap this in a `WithIntent` with the encrypted variant
    pub fn with_intent_encrypted(self) -> WithIntent {
        WithIntent {
            intent: EncryptableKind::Encrypted,
            inner: self,
        }
    }

    /// Wrap this in a `WithIntent` with the plain variant
    pub fn with_intent_plain(self) -> WithIntent {
        WithIntent {
            intent: EncryptableKind::Plain,
            inner: self,
        }
    }
}

/// Shorthand for creating an `Encryptable::Plain` from text (not interpreted as JSON).
pub fn string(s: impl ToString) -> Encryptable {
    Encryptable::Plain(s.to_string().into())
}

/// A wrapper around [`Encryptable`] that also has an intent flag, indicating if we'd like
/// it to be outputted as encrypted or plain.
///
/// Derefs into [`Encryptable`].
///
/// [`Encryptable`]: ./enum.Encryptable.html
#[derive(Debug, Clone)]
pub struct WithIntent {
    intent: EncryptableKind,
    inner: Encryptable,
}

impl WithIntent {
    // Extract the inner `Encryptable`, discarding the intent.
    pub fn into_inner(self) -> Encryptable {
        self.inner
    }

    /// Get the current intent
    pub fn intent(&self) -> EncryptableKind {
        self.intent
    }

    /// Get a mutable reference to the current intent
    pub fn intent_mut(&mut self) -> &mut EncryptableKind {
        &mut self.intent
    }

    /// Set the intent to `EncryptableKind::Encrypted` without changing the underlying `Encryptable`.
    pub fn intend_encrypted(&mut self) -> &mut Self {
        self.intent = EncryptableKind::Encrypted;
        self
    }

    /// Set the intent to `EncryptableKind::Plain` without changing the underlying `Encryptable`.
    pub fn intend_plain(&mut self) -> &mut Self {
        self.intent = EncryptableKind::Plain;
        self
    }

    /// Set the intent to `EncryptableKind::Plain` without changing the underlying `Encryptable`.
    pub fn apply_intent(&mut self, password: &Password) -> Result<(), EnconError> {
        use EncryptableKind::{Encrypted, Plain};

        match (self.inner.kind(), self.intent) {
            (Encrypted, Plain) => {
                self.inner = self
                    .inner
                    .to_decrypted(password)
                    .map_err(EnconError::from)
                    .map_err(|err| err.apply_intent(Plain))?;
            }
            (Plain, Encrypted) => {
                self.inner = self
                    .inner
                    .to_encrypted(password)
                    .map_err(EnconError::from)
                    .map_err(|err| err.apply_intent(Encrypted))?;
            }
            (Plain, Plain) => {}
            (Encrypted, Encrypted) => {}
        }

        Ok(())
    }

    /// Like [`Encryptable::to_decrypted`] but preserving the intent.
    ///
    /// [`Encryptable::to_decrypted`]: ./enum.Encryptable.html#method.to_decrypted
    pub fn to_decrypted(&self, password: &Password) -> Result<Self, DecryptError> {
        Ok(Self {
            inner: self.inner.to_decrypted(password)?,
            intent: self.intent,
        })
    }

    /// Like [`Encryptable::to_encrypted`] but preserving the intent.
    ///
    /// [`Encryptable::to_encrypted`]: ./enum.Encryptable.html#method.to_encrypted
    pub fn to_encrypted(&self, password: &Password) -> Result<Self, EncryptError> {
        Ok(Self {
            inner: self.inner.to_encrypted(password)?,
            intent: self.intent,
        })
    }
}

impl From<Encryptable> for WithIntent {
    fn from(inner: Encryptable) -> Self {
        Self {
            intent: inner.kind(),
            inner,
        }
    }
}

impl Deref for WithIntent {
    type Target = Encryptable;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for WithIntent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Represents a mapping of string keys to [`WithIntent`] values (a wrapper around [`Encryptable`]).
///
/// [`WithIntent`]: ./struct.WithIntent.html
/// [`Encryptable`]: ./enum.Encryptable.html
///
/// # Example
/// ```
/// use encon::Map;
/// use serde_json::json;
/// use serde_json::from_value;
///
/// let map: Map = from_value(json!({
///    "k1": "foo",
///    "k2": {
///        "_encrypted": [
///            "c10a4bed22a6511e0b6724f8c62832a6d85c154272b3b57a355568bb6af62ca99cc98e",
///            "226163081382e58b796fc212e5427546aa9efb2923f561bc7e3b2418ec9166ea69309d",
///            "aa0fee467e6ca538d9f7c29e"
///         ]
///     }
/// })).unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct Map {
    inner: IndexMap<String, WithIntent>,
}

impl Map {
    /// Creates an empty `Map`
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to decrypt all fields with the provided key. This does *not* change the intent
    /// of the fields. You may later call `.apply_all_intents()` to re-encrypt any keys that were
    /// originally encrypted; possibly with a different password.
    pub fn decrypt_all_in_place(&mut self, password: &Password) -> Result<(), EnconError> {
        let mut good_keys = vec![];
        let mut bad_keys = vec![];
        let mut first_error = None;

        for (key, value) in &mut self.inner {
            match value.to_decrypted(password) {
                Ok(decrypted) => {
                    good_keys.push(key.clone());
                    *value = decrypted;
                }
                Err(err) => {
                    bad_keys.push(key.clone());
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        if let Some(source) = first_error {
            Err(EnconError::DecryptAll {
                good_keys,
                bad_keys,
                source: Box::new(source),
            })
        } else {
            Ok(())
        }
    }

    /// Applies the intended state of each field. See [`WithIntent::apply_intent`] for details.
    ///
    /// [`WithIntent::apply_intent`]: ./struct.WithIntent.html#method.apply_intent
    pub fn apply_all_intents(&mut self, password: &Password) -> Result<(), EnconError> {
        for (_, value) in &mut self.inner {
            value.apply_intent(password)?;
        }
        Ok(())
    }

    fn to_json_pre(&self) -> Result<(), MapToJsonError> {
        for (_, value) in &self.inner {
            if value.intent != value.intent() {
                return Err(MapToJsonError::ApplyRequired);
            }
        }

        Ok(())
    }

    /// Converts the `Map` to pretty-printed JSON.
    ///
    /// This method requires that all intents have been applied (use [`apply_all_intents`]
    /// to accomplish this). If intents aren't applied, then [`Err(MapToJsonError::ApplyRequired)`][MapToJsonError::ApplyRequired] will be returned
    ///
    /// [`apply_all_intents`]: #method.apply_all_intents
    /// [MapToJsonError::ApplyRequired]: ./enum.MapToJsonError.html#variant.ApplyRequired
    pub fn to_json_pretty(&self) -> Result<String, MapToJsonError> {
        self.to_json_pre()?;

        serde_json::to_string_pretty(&self.inner).map_err(MapToJsonError::Serde)
    }

    /// Similar to [`to_json_pretty`], except printed as compactly as possible.
    ///
    /// This is `serde_json::to_string`, but named explicitly since you usually want
    /// the `to_json_pretty` variant.
    ///
    /// [`to_json_pretty`]: #method.to_json_pretty
    pub fn to_json_compact(&self) -> Result<String, MapToJsonError> {
        self.to_json_pre()?;

        serde_json::to_string(&self.inner).map_err(MapToJsonError::Serde)
    }

    /// Decrypts all fields and returns a `PlainMap` containing them. This allows you to
    /// skip the plain vs encrypted checks in following code.
    ///
    /// The method clones the keys/values because you may later want to apply changes to the
    /// `PlainMap` back on the `Map`, and then apply the original intents (which are only
    /// stored in `Map`).
    pub fn to_plain_map(&self, password: &Password) -> Result<PlainMap, EnconError> {
        let mut copy = self.clone();
        copy.decrypt_all_in_place(password)?;

        let mut plain_map = PlainMap {
            inner: IndexMap::with_capacity(self.len()),
        };
        for (key, with_intent) in copy {
            match with_intent.into_inner() {
                Encryptable::Plain(value) => {
                    plain_map.insert(key, value);
                }
                _ => panic!(
                    "Expected key {:?} to be decrypted after decrypt_all_in_place",
                    key
                ),
            }
        }

        Ok(plain_map)
    }

    /// Insert a `WithIntent`/`Encryptable`, returning the existing `WithIntent`, if any.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<WithIntent>,
    ) -> Option<WithIntent> {
        self.inner.insert(key.into(), value.into())
    }

    /// Inserts the item before the specified index. If the index is >= the number of items,
    /// it's simply appended to the end.
    ///
    /// ```
    /// use encon::Map;
    /// use encon::Encryptable;
    ///
    /// let mut map = Map::new();
    /// map.insert("foo", encon::string("a"));
    /// map.insert("baz", encon::string("c"));
    /// map.insert_before(1, "bar", encon::string("b"));
    ///
    /// let keys = map.keys().map(|k| k as &str).collect::<Vec<_>>();
    /// assert_eq!(keys, vec!["foo", "bar", "baz"]);
    /// ```
    pub fn insert_before(
        &mut self,
        index: usize,
        key: impl Into<String>,
        value: impl Into<WithIntent>,
    ) -> Option<WithIntent> {
        // Check if we're inserting before an item that doesn't yet exist, i.e. appending
        if index >= self.len() {
            return self.insert(key, value);
        }

        let key = key.into();
        let mut to_insert = Some((key.clone(), value.into()));

        let current_index = self.inner.get_index_of(&key);
        let new_map = IndexMap::with_capacity(if current_index.is_some() {
            self.inner.len()
        } else {
            self.inner.len() + 1
        });

        let inner = std::mem::replace(&mut self.inner, new_map);

        // Try to find an existing item

        let mut ret = None;

        for (i, (k, v)) in inner.into_iter().enumerate() {
            if i == index {
                // This will only be executed once, but no reason to `.unwrap()`
                if let Some((key, value)) = to_insert.take() {
                    self.inner.insert(key, value);
                }
            }

            if current_index == Some(i) {
                ret = Some(v);
            } else {
                self.inner.insert(k, v);
            }
        }

        ret
    }

    /// Return an iterator over the keys of the map, in their order
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.inner.keys()
    }

    /// Return an iterator over the values of the map, in their order
    pub fn values(&self) -> impl Iterator<Item = &WithIntent> {
        self.inner.values()
    }

    /// Get the given key’s corresponding entry in the map for insertion and/or in-place manipulation.
    pub fn entry(&mut self, key: String) -> indexmap::map::Entry<'_, String, WithIntent> {
        self.inner.entry(key)
    }

    /// Return a reference to the value stored for key, if it is present, else None.
    pub fn get(&self, key: impl Into<String>) -> Option<&WithIntent> {
        self.inner.get(&key.into())
    }

    /// Return a mutable reference to the value stored for key, if it is present, else None.
    pub fn get_mut(&mut self, key: impl Into<String>) -> Option<&mut WithIntent> {
        self.inner.get_mut(&key.into())
    }

    /// Returns a double-ended iterator visiting all key-value pairs in order of insertion.
    /// Iterator element type is (&'a String, &'a mut WithIntent)
    pub fn iter(&self) -> indexmap::map::Iter<String, WithIntent> {
        self.inner.iter()
    }

    /// Returns a double-ended iterator visiting all key-value pairs in order of insertion.
    /// Iterator element type is (&'a String, &'a mut WithIntent)
    pub fn iter_mut(&mut self) -> indexmap::map::IterMut<String, WithIntent> {
        self.inner.iter_mut()
    }

    /// Remove the entry for this key, and return it if it exists.
    pub fn remove(&mut self, key: impl Into<String>) -> Option<WithIntent> {
        self.inner.remove(&key.into())
    }

    /// Remove the entry for this key, and return it if it exists.
    pub fn sort_keys(&mut self) {
        self.inner.sort_keys()
    }

    pub fn reverse(&mut self) {
        self.inner.reverse()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl IntoIterator for Map {
    type Item = (String, WithIntent);

    type IntoIter = indexmap::map::IntoIter<String, WithIntent>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a Map {
    type Item = (&'a String, &'a WithIntent);

    type IntoIter = indexmap::map::Iter<'a, String, WithIntent>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Map {
    type Item = (&'a String, &'a mut WithIntent);

    type IntoIter = indexmap::map::IterMut<'a, String, WithIntent>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

// TODO: impl FromIterator<(String, WithIntent)>
// TODO: impl FromIterator<(String, Encryptable)>

/// Similar to [`Map`], but with all fields decrypted into [`Value`s].
///
/// You can acquire this by calling [`Map::to_plain_map`] with a password.
///
/// [`Map`]: struct.Map.html
/// [`Map:to_plain_map`]: struct.Map.html#method.to_plain_map
/// [`Value`s]: https://docs.rs/serde_json/1/serde_json/enum.Value.html
#[derive(Debug, Clone, Default)]
pub struct PlainMap {
    inner: IndexMap<String, Value>,
}

impl PlainMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Converts the `PlainMap` to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, MapToJsonError> {
        serde_json::to_string_pretty(&self.inner).map_err(MapToJsonError::Serde)
    }

    /// Similar to [`to_json_pretty`], except printed as compactly as possible.
    ///
    /// This is `serde_json::to_string`, but named explicitly since you usually want
    /// the `to_json_pretty` variant.
    ///
    /// [`to_json_pretty`]: #method.to_json_pretty
    pub fn to_json_compact(&self) -> Result<String, MapToJsonError> {
        serde_json::to_string(&self.inner).map_err(MapToJsonError::Serde)
    }

    /// Convert this to a [`serde_json::Value`] (in the Object/Map variant).
    ///
    /// [`serde_json::Value`]: https://docs.rs/serde_json/1/serde_json/enum.Value.html
    pub fn to_value(&self) -> Value {
        let map: serde_json::Map<String, Value> =
            self.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        map.into()
    }

    /// Insert a [`Value`], returning the existing `Value`, if any.
    ///
    /// [`Value`]: https://docs.rs/serde_json/1/serde_json/enum.Value.html
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> Option<Value> {
        self.inner.insert(key.into(), value.into())
    }

    /// Inserts the item before the specified index. If the index is >= the number of items,
    /// it's simply appended to the end.
    ///
    /// ```
    /// use encon::PlainMap;
    ///
    /// let mut map = PlainMap::new();
    /// map.insert("foo", serde_json::json!("a"));
    /// map.insert("baz", serde_json::json!("c"));
    /// map.insert_before(1, "bar", serde_json::json!("b"));
    ///
    /// let keys = map.keys().map(|k| k as &str).collect::<Vec<_>>();
    /// assert_eq!(keys, vec!["foo", "bar", "baz"]);
    /// ```
    pub fn insert_before(
        &mut self,
        index: usize,
        key: impl Into<String>,
        value: impl Into<Value>,
    ) -> Option<Value> {
        // TODO: refactor this into a helper to reduce duplication

        // Check if we're inserting before an item that doesn't yet exist, i.e. appending
        if index >= self.len() {
            return self.insert(key, value);
        }

        let key = key.into();
        let mut to_insert = Some((key.clone(), value.into()));

        let current_index = self.inner.get_index_of(&key);
        let new_map = IndexMap::with_capacity(if current_index.is_some() {
            self.inner.len()
        } else {
            self.inner.len() + 1
        });

        let inner = std::mem::replace(&mut self.inner, new_map);

        // Try to find an existing item

        let mut ret = None;

        for (i, (k, v)) in inner.into_iter().enumerate() {
            if i == index {
                // This will only be executed once, but no reason to `.unwrap()`
                if let Some((key, value)) = to_insert.take() {
                    self.inner.insert(key, value);
                }
            }

            if current_index == Some(i) {
                ret = Some(v);
            } else {
                self.inner.insert(k, v);
            }
        }

        ret
    }

    /// Return an iterator over the keys of the map, in their order
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.inner.keys()
    }

    /// Return an iterator over the values of the map, in their order
    pub fn values(&self) -> impl Iterator<Item = &Value> {
        self.inner.values()
    }

    /// Get the given key’s corresponding entry in the map for insertion and/or in-place manipulation.
    pub fn entry(&mut self, key: String) -> indexmap::map::Entry<'_, String, Value> {
        self.inner.entry(key)
    }

    /// Return a reference to the value stored for key, if it is present, else None.
    pub fn get(&self, key: impl Into<String>) -> Option<&Value> {
        self.inner.get(&key.into())
    }

    /// Return a mutable reference to the value stored for key, if it is present, else None.
    pub fn get_mut(&mut self, key: impl Into<String>) -> Option<&mut Value> {
        self.inner.get_mut(&key.into())
    }

    /// Returns a double-ended iterator visiting all key-value pairs in order of insertion.
    /// Iterator element type is (&'a String, &'a mut Value)
    pub fn iter(&self) -> indexmap::map::Iter<String, Value> {
        self.inner.iter()
    }

    /// Returns a double-ended iterator visiting all key-value pairs in order of insertion.
    /// Iterator element type is (&'a String, &'a mut Value)
    pub fn iter_mut(&mut self) -> indexmap::map::IterMut<String, Value> {
        self.inner.iter_mut()
    }

    /// Remove the entry for this key, and return it if it exists.
    pub fn remove(&mut self, key: impl Into<String>) -> Option<Value> {
        self.inner.remove(&key.into())
    }

    /// Remove the entry for this key, and return it if it exists.
    pub fn sort_keys(&mut self) {
        self.inner.sort_keys()
    }

    pub fn reverse(&mut self) {
        self.inner.reverse()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl IntoIterator for PlainMap {
    type Item = (String, Value);

    type IntoIter = indexmap::map::IntoIter<String, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a PlainMap {
    type Item = (&'a String, &'a Value);

    type IntoIter = indexmap::map::Iter<'a, String, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut PlainMap {
    type Item = (&'a String, &'a mut Value);

    type IntoIter = indexmap::map::IterMut<'a, String, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::Encryptable;
    use serde_json::json;

    #[test]
    fn deserialize_encrypted() {
        let enc: Encryptable = serde_json::from_value(json!({
            "_encrypted": [
                "010203",
                "040506"
            ]
        }))
        .expect("deserialize");

        assert_eq!(
            enc.as_encrypted().expect("as_encrypted"),
            &[1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn deserialize_other_object() {
        let value = json!({
            "_encrypted": [
                "NOT_HEX",
                "040506"
            ]
        });

        let enc: Encryptable = serde_json::from_value(value.clone()).expect("deserialize");

        assert_eq!(enc.as_plain().expect("as_plain"), &value);
    }
}
