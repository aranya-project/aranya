use core::ops::{Deref, DerefMut};

use anyhow::Result;
use aranya_crypto::{
    engine::WrappedKey,
    id::BaseId,
    keystore::{self, fs_keystore, KeyStore, Occupied, Vacant},
};

macro_rules! impl_typed_keystore {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug)]
        $vis struct $name<S>(S);

        impl<S> $name<S> {
            /// Creates a new
            #[doc = concat!("`", stringify!($name), "`.")]
            #[inline]
            pub fn new(store: S) -> Self {
                Self(store)
            }
        }

        impl<S: KeyStore> KeyStore for $name<S> {
            type Error = <S as KeyStore>::Error;
            type Vacant<'a, T: WrappedKey> = VacantEntry<<S as KeyStore>::Vacant<'a, T>>;
            type Occupied<'a, T: WrappedKey> = OccupiedEntry<<S as KeyStore>::Occupied<'a, T>>;

            #[inline]
            fn entry<T: WrappedKey>(
                &mut self,
                id: BaseId,
            ) -> Result<keystore::Entry<'_, Self, T>, Self::Error> {
                use keystore::Entry;
                self.0.entry(id).map(|entry| match entry {
                    Entry::Vacant(entry) => Entry::Vacant(VacantEntry(entry)),
                    Entry::Occupied(entry) => Entry::Occupied(OccupiedEntry(entry)),
                })
            }

            #[inline]
            fn get<T: WrappedKey>(&self, id: BaseId) -> Result<Option<T>, Self::Error> {
                self.0.get(id)
            }

            #[inline]
            fn try_insert<T: WrappedKey>(
                &mut self,
                id: BaseId,
                key: T,
            ) -> Result<(), Self::Error> {
                self.0.try_insert(id, key)
            }

            #[inline]
            fn remove<T: WrappedKey>(
                &mut self,
                id: BaseId,
            ) -> Result<Option<T>, Self::Error> {
                self.0.remove(id)
            }
        }

        impl<S> Deref for $name<S> {
            type Target = S;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<S> DerefMut for $name<S> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl $name<fs_keystore::Store> {
            /// Attempts to clone the keystore.
            #[allow(dead_code, reason = "Depends on the impl")]
            #[inline]
            pub fn try_clone(&self) -> Result<Self> {
                let store = self.0.try_clone()?;
                Ok(Self(store))
            }
        }
    };
}

impl_typed_keystore! {
    /// The Aranya keystore.
    ///
    /// The Aranaya keystore contains Aranya's key material.
    pub struct AranyaStore;
}

/// A vacant entry.
#[derive(Debug)]
pub struct VacantEntry<E>(E);

impl<E, T> Vacant<T> for VacantEntry<E>
where
    E: Vacant<T>,
    T: WrappedKey,
{
    type Error = <E as Vacant<T>>::Error;

    fn insert(self, key: T) -> Result<(), Self::Error> {
        self.0.insert(key)
    }
}

/// An occupied entry.
#[derive(Debug)]
pub struct OccupiedEntry<E>(E);

impl<E, T> Occupied<T> for OccupiedEntry<E>
where
    E: Occupied<T>,
    T: WrappedKey,
{
    type Error = <E as Occupied<T>>::Error;

    fn get(&self) -> Result<T, Self::Error> {
        self.0.get()
    }

    fn remove(self) -> Result<T, Self::Error> {
        self.0.remove()
    }
}
