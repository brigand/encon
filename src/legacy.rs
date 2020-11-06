use crate::error::{DecryptError, EncryptError};
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::{Header, Key};
use sodiumoxide::crypto::secretstream::{Stream, Tag, ABYTES, HEADERBYTES, KEYBYTES};
use std::io::Write as _;
use std::sync::Arc;

const CHUNKSIZE: usize = 4096;
pub const SIGNATURE: [u8; 4] = [0xC1, 0x0A, 0x4B, 0xED];

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

        let mut key = [0u8; KEYBYTES];
        pwhash::derive_key(
            &mut key,
            self.password.as_bytes(),
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let key = Key(key);

        let mut offset = 0;
        let (mut stream, header) = Stream::init_push(&key).map_err(|_| EncryptError::Init)?;
        output.write_all(&header.0).map_err(EncryptError::write)?;

        while offset < bytes.len() {
            let bytes_left = bytes.len().saturating_sub(offset);
            let tag = match bytes_left {
                0 => Tag::Final,
                _ => Tag::Message,
            };

            let end = std::cmp::min(offset + CHUNKSIZE, bytes.len());

            output
                .write_all(
                    &stream
                        .push(&bytes[offset..end], None, tag)
                        .map_err(|_| EncryptError::EncryptChunk)?,
                )
                .map_err(EncryptError::write)?;

            offset += CHUNKSIZE;
        }

        Ok(output)
    }

    /// Decrypt a byte slice with this password.
    ///
    /// # Example
    /// Here is a known working example.
    ///
    /// ```
    /// use encon::legacy::Password;
    ///
    /// let password = Password::new("strongpassword");
    /// let buffer = password.decrypt(vec![
    ///     0xc1, 0x0a, 0x4b, 0xed, 0x72, 0xa5, 0xb6, 0xec, 0xa2, 0xb2, 0x77, 0xcd,
    ///     0x5f, 0x4b, 0xa1, 0x1e, 0x70, 0x73, 0x01, 0xd3, 0xbd, 0xb0, 0x5f, 0x9f,
    ///     0xfa, 0x69, 0xfc, 0x9a, 0xf2, 0x28, 0xa7, 0x51, 0xc4, 0x70, 0xe0, 0x68,
    ///     0x2f, 0x04, 0x90, 0x1a, 0xbc, 0xfc, 0xf4, 0x79, 0x14, 0x94, 0x38, 0x1f,
    ///     0x0a, 0x36, 0xf2, 0xe1, 0x1f, 0x67, 0x87, 0x9b, 0x13, 0x01, 0xb3, 0x8b,
    ///     0x1b, 0xff, 0x41, 0xce, 0x15, 0xef, 0x13, 0xdc, 0x57, 0xf1, 0xc0, 0x65,
    ///     0x5a, 0x00, 0x3d, 0x23, 0xc8, 0x04, 0x4e, 0xe7, 0xd4, 0x29, 0x62, 0xa0,
    ///     0x85, 0x98, 0x04, 0x36, 0xea, 0xdf,
    /// ]).unwrap();
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
        if bytes.len() <= (pwhash::SALTBYTES + HEADERBYTES + SIGNATURE.len()) {
            return Err(DecryptError::InputTooShort);
        }

        let mut offset = 0;

        let mut salt = [0u8; pwhash::SALTBYTES];
        let mut signature = [0u8; 4];

        signature.copy_from_slice(&bytes[offset..offset + SIGNATURE.len()]);
        offset += signature.len();
        salt.copy_from_slice(&bytes[offset..offset + pwhash::SALTBYTES]);
        offset += salt.len();

        let salt = pwhash::Salt(salt);

        let mut header = [0u8; HEADERBYTES];

        header.copy_from_slice(&bytes[offset..offset + HEADERBYTES]);
        offset += header.len();

        let header = Header(header);

        let mut key = [0u8; KEYBYTES];
        pwhash::derive_key(
            &mut key,
            self.password.as_bytes(),
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .map_err(|_| DecryptError::DeriveKey)?;
        let key = Key(key);

        let mut stream = Stream::init_pull(&header, &key).map_err(|_| DecryptError::Init)?;

        let mut output = Vec::new();

        while stream.is_not_finalized() {
            if offset >= bytes.len() {
                break;
            }

            let end = std::cmp::min(offset + CHUNKSIZE + ABYTES, bytes.len());

            let (decrypted, _tag) = stream
                .pull(&bytes[offset..end], None)
                .map_err(|_| DecryptError::LikelyWrongPassword)?;
            output.write_all(&decrypted).map_err(DecryptError::write)?;

            offset = end;
        }

        Ok(output)
    }
}

impl From<super::Password> for Password {
    fn from(pass: super::Password) -> Self {
        Self {
            password: pass.password,
        }
    }
}
