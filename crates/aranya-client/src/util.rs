macro_rules! custom_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $crate::util::custom_id!($vis struct $name => $name;);
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident => $api:ident;
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone, core::hash::Hash, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $name(aranya_daemon_api::$api);

        impl $name {
            pub(crate) fn into_api(self) -> aranya_daemon_api::$api {
                self.0.into_id().into()
            }

            #[allow(dead_code, reason = "Depends on the type.")]
            pub(crate) fn from_api(id: aranya_daemon_api::$api) -> Self {
                Self(id.into_id().into())
            }
        }

        #[doc(hidden)]
        impl From<[u8; 64]> for $name {
            #[inline]
            fn from(id: [u8; 64]) -> Self {
                Self(id.into())
            }
        }

        #[doc(hidden)]
        impl From<$name> for [u8;64] {
            #[inline]
            fn from(id: $name) -> Self {
                id.0.into()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }
    };
}
pub(crate) use custom_id;
