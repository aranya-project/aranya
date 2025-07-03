use serde::{de, ser, Deserialize, Serialize};

/// Serde wrapper for an `enable` field on an optional.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Toggle<T> {
    /// An enabled option.
    ///
    /// This will serialize as `{ enable: true, ...T }`.
    Enabled(T),
    /// A disabled option.
    ///
    /// This will serialize as `{ enable: false }`.
    #[default]
    Disabled,
}

// TODO: Impl manually? Validate fields in disabled case?
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Toggle<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        imp::E::deserialize(deserializer).map(Self::from)
    }
}

impl<T: Serialize> Serialize for Toggle<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        imp::E::from(self).serialize(serializer)
    }
}

mod imp {
    use serde::{de, ser, Deserialize, Serialize};

    use super::Toggle;

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

    impl<'a, T> From<&'a Toggle<T>> for E<&'a T> {
        fn from(toggle: &'a Toggle<T>) -> E<&'a T> {
            match toggle {
                Toggle::Enabled(fields) => Self::Enabled {
                    enable: True,
                    fields,
                },
                Toggle::Disabled => Self::Disabled { enable: False },
            }
        }
    }

    impl<T> From<E<T>> for Toggle<T> {
        fn from(value: E<T>) -> Self {
            match value {
                E::Enabled {
                    enable: True,
                    fields,
                } => Toggle::Enabled(fields),
                E::Disabled { enable: False } => Toggle::Disabled,
            }
        }
    }
}
