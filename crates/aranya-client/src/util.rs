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
        impl From<aranya_crypto::Id> for $name {
            #[inline]
            fn from(id: aranya_crypto::Id) -> Self {
                Self(id.into())
            }
        }

        #[doc(hidden)]
        impl From<[u8; 32]> for $name {
            #[inline]
            fn from(id: [u8; 32]) -> Self {
                Self(id.into())
            }
        }

        #[doc(hidden)]
        impl From<$name> for [u8; 32] {
            #[inline]
            fn from(id: $name) -> Self {
                id.0.into()
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(&self.0, f)
            }
        }
    };
}
pub(crate) use custom_id;
