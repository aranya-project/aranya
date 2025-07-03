use serde::{de, ser, Deserialize, Serialize};

/// Serde wrapper for an `enable` field on an optional.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Enable<T>(pub Option<T>);

impl<T> Enable<T> {
    /// Create an enabled value.
    pub const fn enabled(value: T) -> Self {
        Self(Some(value))
    }

    /// Create a disabled value.
    pub const fn disabled() -> Self {
        Self(None)
    }
}

impl<T> Default for Enable<T> {
    fn default() -> Self {
        Self(None)
    }
}

// TODO: Impl manually? Validate fields in disabled case?
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Enable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = imp::E::deserialize(deserializer)?;
        Ok(Enable(value.into()))
    }
}

impl<T: Serialize> Serialize for Enable<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let value = imp::E::from(self.0.as_ref());
        value.serialize(serializer)
    }
}

mod imp {
    use serde::{de, ser, Deserialize, Serialize};

    pub struct True;
    impl<'de> Deserialize<'de> for True {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            if bool::deserialize(deserializer)? {
                Ok(Self)
            } else {
                Err(de::Error::invalid_value(
                    de::Unexpected::Bool(false),
                    &"the `true` boolean",
                ))
            }
        }
    }
    impl Serialize for True {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bool(true)
        }
    }

    #[derive(Default)]
    pub struct False;
    impl<'de> Deserialize<'de> for False {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            if bool::deserialize(deserializer)? {
                Ok(Self)
            } else {
                Err(de::Error::invalid_value(
                    de::Unexpected::Bool(true),
                    &"the `false` boolean",
                ))
            }
        }
    }
    impl Serialize for False {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bool(false)
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum E<T> {
        Enabled {
            enable: True,
            #[serde(flatten)]
            fields: T,
        },
        Disabled {
            #[serde(default)]
            enable: False,
        },
    }

    impl<T> From<Option<T>> for E<T> {
        fn from(value: Option<T>) -> Self {
            if let Some(fields) = value {
                E::Enabled {
                    enable: True,
                    fields,
                }
            } else {
                E::Disabled { enable: False }
            }
        }
    }

    impl<T> From<E<T>> for Option<T> {
        fn from(value: E<T>) -> Self {
            match value {
                E::Enabled {
                    enable: True,
                    fields,
                } => Some(fields),
                E::Disabled { enable: False } => None,
            }
        }
    }
}
