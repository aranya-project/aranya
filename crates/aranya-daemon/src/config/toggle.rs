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
        imp::ToggleRepr::deserialize(deserializer).map(Self::from)
    }
}

impl<T: Serialize> Serialize for Toggle<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        imp::ToggleRepr::from(self).serialize(serializer)
    }
}

mod imp {
    #![expect(
        missing_debug_implementations,
        reason = "Types are only used for serialization"
    )]
    #![expect(clippy::use_self, reason = "Explicit True/False is more clear")]

    use serde::{de, ser, Deserialize, Serialize};

    use super::Toggle;

    pub struct True;
    impl<'de> Deserialize<'de> for True {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            match bool::deserialize(deserializer)? {
                true => Ok(True),
                false => Err(de::Error::invalid_value(
                    de::Unexpected::Bool(false),
                    &"the `true` boolean",
                )),
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
            match bool::deserialize(deserializer)? {
                false => Ok(False),
                true => Err(de::Error::invalid_value(
                    de::Unexpected::Bool(true),
                    &"the `false` boolean",
                )),
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
    pub enum ToggleRepr<T> {
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

    impl<'a, T> From<&'a Toggle<T>> for ToggleRepr<&'a T> {
        fn from(toggle: &'a Toggle<T>) -> Self {
            match toggle {
                Toggle::Enabled(fields) => Self::Enabled {
                    enable: True,
                    fields,
                },
                Toggle::Disabled => Self::Disabled { enable: False },
            }
        }
    }

    impl<T> From<ToggleRepr<T>> for Toggle<T> {
        fn from(value: ToggleRepr<T>) -> Self {
            match value {
                ToggleRepr::Enabled {
                    enable: True,
                    fields,
                } => Self::Enabled(fields),
                ToggleRepr::Disabled { enable: False } => Self::Disabled,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::disallowed_macros, reason = "unreachable in toml macro")]

    use serde::{Deserialize, Serialize};
    use toml::toml;

    use super::Toggle;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Thing {
        field: i64,
    }

    #[test]
    fn test_enabled_with_field() {
        let table = toml! {
            enable = true
            field = 42
        };
        assert_eq!(
            table.try_into::<Toggle<Thing>>(),
            Ok(Toggle::Enabled(Thing { field: 42 }))
        );
    }

    #[test]
    fn test_enabled_without_field() {
        let table = toml! {
            enable = true
        };
        let err = table.try_into::<Toggle<Thing>>().unwrap_err();
        // TODO(jdygert): Improve error.
        assert_eq!(
            err,
            serde::de::Error::custom("data did not match any variant of untagged enum ToggleRepr")
        );
    }

    #[test]
    fn test_enabled_with_unknown_field() {
        // TODO(jdygert): Deny unknown fields?
        let table = toml! {
            enable = true
            field = 42
            unknown = 0
        };
        assert_eq!(
            table.try_into::<Toggle<Thing>>(),
            Ok(Toggle::Enabled(Thing { field: 42 }))
        );
    }

    #[test]
    fn test_disabled_with_field() {
        let table = toml! {
            enable = false
            field = 42
        };
        assert_eq!(table.try_into::<Toggle<Thing>>(), Ok(Toggle::Disabled));
    }

    #[test]
    fn test_disabled_without_field() {
        let table = toml! {
            enable = false
        };
        assert_eq!(table.try_into::<Toggle<Thing>>(), Ok(Toggle::Disabled));
    }

    #[test]
    fn test_empty() {
        let table = toml::Table::default();
        assert_eq!(table.try_into::<Toggle<Thing>>(), Ok(Toggle::Disabled));
    }

    #[test]
    fn test_no_enable_with_field() {
        let table = toml! {
            unknown = 0
        };
        assert_eq!(table.try_into::<Toggle<Thing>>(), Ok(Toggle::Disabled));
    }
}
