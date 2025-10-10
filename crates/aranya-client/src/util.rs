macro_rules! custom_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $crate::util::custom_id! {
            $(#[$meta])*
            $vis struct $name => $name;
        }
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident => $api:ident;
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone, core::hash::Hash, Eq, PartialEq, Ord, PartialOrd)]
        $vis struct $name(aranya_daemon_api::$api);

        impl $name {
            #[doc(hidden)]
            #[allow(dead_code, reason = "Depends on the type.")]
            pub fn into_api(self) -> aranya_daemon_api::$api {
                self.0.into_id().into()
            }

            #[doc(hidden)]
            #[allow(dead_code, reason = "Depends on the type.")]
            pub fn from_api(id: aranya_daemon_api::$api) -> Self {
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

/// Implement iterator traits for newtype wrappers
/// over `slice::Iter`.
macro_rules! impl_slice_iter_wrapper {
    ($wrapper:ident <$lifetime:lifetime> for $item:ty) => {
        impl<$lifetime> Iterator for $wrapper<$lifetime> {
            type Item = &$lifetime $item;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                self.0.next()
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }

            #[inline]
            fn count(self) -> usize {
                self.0.count()
            }

            #[inline]
            fn nth(&mut self, n: usize) -> Option<Self::Item> {
                self.0.nth(n)
            }

            #[inline]
            fn last(self) -> Option<Self::Item> {
                self.0.last()
            }

            #[inline]
            fn fold<B, F>(self, init: B, f: F) -> B
            where
                F: FnMut(B, Self::Item) -> B,
            {
                self.0.fold(init, f)
            }

            #[inline]
            fn for_each<F>(self, f: F)
            where
                F: FnMut(Self::Item),
            {
                self.0.for_each(f)
            }

            #[inline]
            fn all<F>(&mut self, f: F) -> bool
            where
                F: FnMut(Self::Item) -> bool,
            {
                self.0.all(f)
            }

            #[inline]
            fn any<F>(&mut self, f: F) -> bool
            where
                F: FnMut(Self::Item) -> bool,
            {
                self.0.any(f)
            }

            #[inline]
            fn find<P>(&mut self, predicate: P) -> Option<Self::Item>
            where
                P: FnMut(&Self::Item) -> bool,
            {
                self.0.find(predicate)
            }

            #[inline]
            fn position<P>(&mut self, predicate: P) -> Option<usize>
            where
                P: FnMut(Self::Item) -> bool,
            {
                self.0.position(predicate)
            }

            #[inline]
            fn rposition<P>(&mut self, predicate: P) -> Option<usize>
            where
                P: FnMut(Self::Item) -> bool,
            {
                self.0.rposition(predicate)
            }
        }

        impl<$lifetime> DoubleEndedIterator for $wrapper<$lifetime> {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                self.0.next_back()
            }

            #[inline]
            fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                self.0.nth_back(n)
            }
        }

        impl<$lifetime> ExactSizeIterator for $wrapper<$lifetime> {
            #[inline]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl<$lifetime> ::core::iter::FusedIterator for $wrapper<$lifetime> {}
    };
}
pub(crate) use impl_slice_iter_wrapper;

/// Implement iterator traits for newtype wrappers over
/// `vec::IntoIter`.
macro_rules! impl_vec_into_iter_wrapper {
    ($wrapper:ident for $item:ty) => {
        impl Iterator for $wrapper {
            type Item = $item;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                self.0.next()
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }

            #[inline]
            fn count(self) -> usize {
                self.0.count()
            }

            #[inline]
            fn last(self) -> Option<Self::Item> {
                self.0.last()
            }

            #[inline]
            fn fold<B, F>(self, init: B, f: F) -> B
            where
                F: FnMut(B, Self::Item) -> B,
            {
                self.0.fold(init, f)
            }
        }

        impl DoubleEndedIterator for $wrapper {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                self.0.next_back()
            }
        }

        impl ExactSizeIterator for $wrapper {
            #[inline]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl ::core::iter::FusedIterator for $wrapper {}
    };
}
pub(crate) use impl_vec_into_iter_wrapper;
