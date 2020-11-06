use crate::util::to_hex_vec;
use crate::Encryptable;
use crate::EncryptableKind;
use crate::Map;
use crate::WithIntent;
use indexmap::map::IndexMap;
use serde::de;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

impl Serialize for Encryptable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Encrypted(bytes) => {
                let hex = to_hex_vec(bytes);
                let mut struct_ = serializer.serialize_struct("Encryptable", 1)?;
                struct_.serialize_field("_encrypted", &hex)?;
                struct_.end()
            }
            Self::Plain(value) => serializer.serialize_newtype_struct("Encryptable", value),
        }
    }
}

impl<'de> Deserialize<'de> for Encryptable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Encryptable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "an object with an _encrypted: Array<HexString> or any other value"
                )
            }

            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                de::Deserialize::deserialize(de::value::MapAccessDeserializer::new(map)).and_then(
                    |map: serde_json::Value| {
                        if let Some(encrypted) = map.get("_encrypted") {
                            if let Some(array) = encrypted.as_array() {
                                let mut buffer = Vec::with_capacity(32);
                                let mut valid = false;
                                for s in array {
                                    if let Some(bytes) =
                                        s.as_str().and_then(|s| hex::decode(s).ok())
                                    {
                                        buffer.extend(bytes);
                                        valid = true;
                                    } else {
                                        valid = false;
                                        break;
                                    }
                                }

                                if valid {
                                    return Ok(Encryptable::Encrypted(buffer));
                                }
                            }
                        }

                        return Ok(Encryptable::Plain(map.into()));
                    },
                )
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain(v.into()))
            }

            fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain((v as f64).into()))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain(v.into()))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain(v.into()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain(v.into()))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Encryptable::Plain(Value::Null))
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                de::Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
                    .map(Encryptable::Plain)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl<'de> Deserialize<'de> for Map {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        IndexMap::deserialize(deserializer).map(|map| Map { inner: map })
    }
}

impl<'de> Deserialize<'de> for WithIntent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Encryptable::deserialize(deserializer).map(|enc| WithIntent {
            intent: match enc {
                Encryptable::Encrypted(_) => EncryptableKind::Encrypted,
                Encryptable::Plain(_) => EncryptableKind::Plain,
            },
            inner: enc,
        })
    }
}
impl Serialize for WithIntent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}
