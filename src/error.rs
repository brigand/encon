use crate::EncryptableKind;
use std::error::Error;
use std::fmt;
use std::io;
use std::string::FromUtf8Error;

/// High level error enum for when a single error type like [`DecryptError`] is too specific.
///
/// [`DecryptError`]: ./DecryptError.enum.html
#[derive(Debug)]
pub enum EnconError {
    Encrypt(EncryptError),
    Decrypt(DecryptError),
    ApplyIntent {
        target_kind: EncryptableKind,
        source: Box<dyn Error + Send>,
    },
    DecryptAll {
        good_keys: Vec<String>,
        bad_keys: Vec<String>,
        source: Box<dyn Error + Send>,
    },
    MapToJson(MapToJson),
}

impl EnconError {
    pub(crate) fn apply_intent(self, target_kind: EncryptableKind) -> Self {
        EnconError::ApplyIntent {
            target_kind,
            source: Box::new(self),
        }
    }
}

impl From<EncryptError> for EnconError {
    fn from(source: EncryptError) -> Self {
        Self::Encrypt(source)
    }
}

impl From<DecryptError> for EnconError {
    fn from(source: DecryptError) -> Self {
        Self::Decrypt(source)
    }
}

impl fmt::Display for EnconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt(_) => write!(f, "An error ocurred while encrypting"),
            Self::Decrypt(_) => write!(f, "An error ocurred while decrypting"),
            Self::ApplyIntent { target_kind, .. } => {
                write!(f, "Failed to transition the field to {}", target_kind)
            }
            Self::DecryptAll {
                good_keys,
                bad_keys,
                ..
            } => {
                if bad_keys.is_empty() {
                    write!(
                        f,
                        "Unexpected case where decrypt-all failed, but no failed keys were found."
                    )
                } else if good_keys.is_empty() {
                    write!(f, "Decrypt-all failed for all keys: {:?}.", bad_keys)
                } else {
                    write!(
                        f,
                        "Decrypt-all failed for some keys. Good: {:?}. Bad: {:?}",
                        good_keys, bad_keys
                    )
                }
            }
            Self::MapToJson(ref err) => match err {
                MapToJson::ApplyRequired => write!(
                    f,
                    "Converting the Map to JSON failed due to unapplied intents"
                ),
                _ => write!(
                    f,
                    "Converting the Map to JSON failed for a reason other than unapplied intents"
                ),
            },
        }
    }
}

impl Error for EnconError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encrypt(source) => Some(&*source),
            Self::Decrypt(source) => Some(&*source),
            Self::ApplyIntent { source, .. } => Some(source.as_ref()),
            Self::DecryptAll { source, .. } => Some(source.as_ref()),
            Self::MapToJson(source) => Some(&*source),
        }
    }

    // fn backtrace(&self) -> Option<&std::backtrace::Backtrace> {
    //     None
    // }
}

/// An error that may arise during encryption. Generally it's expected that encryption doesn't
/// fail.
///
/// If it does you can match on the error, and for the `Write` and `Serialize` variants,
/// there's an underlying source value (see the `std::error::Error` trait).
#[derive(Debug)]
pub enum EncryptError {
    Init,
    EncryptChunk,
    Write { source: io::Error },
    Serialize { source: serde_json::Error },
}

impl EncryptError {
    pub(crate) fn write(source: io::Error) -> Self {
        Self::Write { source }
    }

    pub(crate) fn serialize(source: serde_json::Error) -> Self {
        Self::Serialize { source }
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Init => "Unable to initialize the encryption",
                Self::EncryptChunk => "Unable to encrypt a chunk",
                Self::Write { .. } => "An underlying IO error ocurred during encryption",
                Self::Serialize { .. } => "Failed to serialize the value to JSON",
            }
        )
    }
}

impl Error for EncryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Write { source } => Some(&*source),
            Self::Serialize { source } => Some(&*source),
            _ => None,
        }
    }

    // fn backtrace(&self) -> Option<&std::backtrace::Backtrace> {
    //     None
    // }
}

/// An error that may arise during decryption.
///
/// The main cases you want to handle are `LikelyWrongPassword` and `InputTooShort`. The
/// former indicates the password is wrong, and the latter indicates that the encrypted
/// blob is invalid.
///
/// For the `Write`, `Serialize`, and `Utf8` variants,
/// there's an underlying source value (see the `std::error::Error` trait).
#[derive(Debug)]
pub enum DecryptError {
    InputTooShort,
    DeriveKey,
    Init,
    LikelyWrongPassword,
    Write { source: io::Error },
    Deserialize { source: serde_json::Error },
    Utf8 { source: FromUtf8Error },
}

impl DecryptError {
    pub(crate) fn write(source: io::Error) -> Self {
        Self::Write { source }
    }

    pub(crate) fn deserialize(source: serde_json::Error) -> Self {
        Self::Deserialize { source }
    }

    pub(crate) fn utf8(source: FromUtf8Error) -> Self {
        Self::Utf8 { source }
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InputTooShort => "The provided input is too short to decrypt",
                Self::DeriveKey => "Unable to derive a decryption key from the provided password",
                Self::Init => "Unable to initialize the decryption",
                Self::LikelyWrongPassword => "Unable to decrypt, likely due to an invalid password",
                Self::Write { .. } => "An underlying IO error ocurred during decryption",
                Self::Deserialize { .. } =>
                    "Failed to deserialize the encrypted value (invalid JSON)",
                Self::Utf8 { .. } => "The decrypted data produced invalid UTF8 bytes",
            }
        )
    }
}

impl Error for DecryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Write { source } => Some(&*source),
            Self::Deserialize { source } => Some(&*source),
            Self::Utf8 { source } => Some(&*source),
            _ => None,
        }
    }

    // fn backtrace(&self) -> Option<&std::backtrace::Backtrace> {
    //     None
    // }
}

/// An error arising from converting a `Map` to JSON (either pretty or compact)
///
/// The `ApplyRequired` variant means you need to call `map.apply_all_intents(password)?`
/// before the `to_json` methods.
#[derive(Debug)]
pub enum MapToJson {
    ApplyRequired,
    Serde(serde_json::Error),
}

impl fmt::Display for MapToJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplyRequired => write!(
                f,
                "You must apply all intents before converting a Map to JSON"
            ),
            Self::Serde(_) => write!(f, "A serialization error ocurred"),
        }
    }
}

impl Error for MapToJson {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serde(source) => Some(&*source),
            Self::ApplyRequired => None,
        }
    }
}
