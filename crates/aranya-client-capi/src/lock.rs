use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

/// Tried to lock an already-locked lock.
pub struct AlreadyLocked;

/// A mutex-like type which only supports `try_lock`.
pub struct Lock<T> {
    value: UnsafeCell<T>,
    is_locked: AtomicBool,
}

impl<T> Lock<T> {
    pub fn new(value: T) -> Self {
        Self {
            is_locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn try_lock(&self) -> Result<Guard<'_, T>, AlreadyLocked> {
        if self.is_locked.swap(true, Ordering::Acquire) {
            return Err(AlreadyLocked);
        }
        Ok(Guard {
            // SAFETY: `UnsafeCell::get` is non-null.
            value: unsafe { NonNull::new_unchecked(self.value.get()) },
            is_locked: &self.is_locked,
        })
    }
}

pub struct Guard<'a, T> {
    value: NonNull<T>,
    is_locked: &'a AtomicBool,
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.is_locked.store(false, Ordering::Release);
    }
}

impl<T> core::ops::Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: `value` is valid while `Guard` is live.
        unsafe { self.value.as_ref() }
    }
}

impl<T> core::ops::DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: `value` is valid while `Guard` is live.
        unsafe { self.value.as_mut() }
    }
}
