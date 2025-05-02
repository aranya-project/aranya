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
        ::aranya_crypto::custom_id! {
            $(#[$meta])*
            $vis struct $name;
        }

        impl $name {
            pub(crate) fn into_api(self) -> aranya_daemon_api::$api {
                self.into_id().into()
            }

            #[allow(dead_code, reason = "Depends on the type.")]
            pub(crate) fn from_api(id: aranya_daemon_api::$api) -> Self {
                id.into_id().into()
            }
        }
    };
}
pub(crate) use custom_id;
