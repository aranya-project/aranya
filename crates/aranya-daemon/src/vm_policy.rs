#![allow(missing_docs)]

use std::{fmt, marker::PhantomData};

use anyhow::{Context, Result};
use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::{
    keystore::{fs_keystore::Store, KeyStore},
    DeviceId,
};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{ffi::FfiModule, Machine};
use aranya_runtime::{
    FfiCallable, PolicyError, PolicyId, PolicyStore, Sink, VmEffect, VmPolicy,
};
use tracing::instrument;

use crate::{
    keystore::AranyaStore,
    policy::{ChanOp, RoleManagementPerm, SimplePerm},
    util::TryClone,
};

/// Policy loaded from policy.md file.
pub(crate) const POLICY_SOURCE: &str = include_str!("./policy.md");

/// Display implementation for [`ChanOp`]
impl fmt::Display for ChanOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChanOp::{self:?}")
    }
}

/// Display implementation for [`RoleManagementPerm`]
impl fmt::Display for RoleManagementPerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoleManagementPerm::{self:?}")
    }
}

/// Display implementation for [`SimplePerm`]
impl fmt::Display for SimplePerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SimplePerm::{self:?}")
    }
}

/// Engine using policy from [`policy.md`].
pub struct PolicyEngine<E, KS> {
    /// The underlying policy.
    pub(crate) policy: VmPolicy<E>,
    _eng: PhantomData<E>,
    _ks: PhantomData<KS>,
}

impl<E, KS> PolicyEngine<E, KS>
where
    E: aranya_crypto::Engine,
    KS: KeyStore + TryClone + Send + 'static,
{
    /// Creates a `PolicyEngine` from a policy document.
    pub fn new(
        policy_doc: &str,
        eng: E,
        store: AranyaStore<KS>,
        device_id: DeviceId,
    ) -> Result<Self> {
        // compile the policy.
        let ast = parse_policy_document(policy_doc).context("unable to parse policy document")?;
        let module = Compiler::new(&ast)
            .ffi_modules(&[
                AfcFfi::<Store>::SCHEMA,
                CryptoFfi::<Store>::SCHEMA,
                DeviceFfi::SCHEMA,
                EnvelopeFfi::SCHEMA,
                IdamFfi::<Store>::SCHEMA,
                PerspectiveFfi::SCHEMA,
            ])
            .compile()
            .context("should be able to compile policy")?;
        let machine = Machine::from_module(module).context("should be able to create machine")?;

        // select which FFI modules to use.
        let ffis: Vec<Box<dyn FfiCallable<E> + Send + 'static>> = vec![
            Box::from(AfcFfi::new(store.try_clone()?)),
            Box::from(CryptoFfi::new(store.try_clone()?)),
            Box::from(DeviceFfi::new(device_id)),
            Box::from(EnvelopeFfi),
            Box::from(IdamFfi::new(store)),
            Box::from(PerspectiveFfi),
        ];

        // create an instance of the policy VM.
        let policy = VmPolicy::new(machine, eng, ffis).context("unable to create `VmPolicy`")?;
        Ok(Self {
            policy,
            _eng: PhantomData,
            _ks: PhantomData,
        })
    }
}

impl<E, KS> PolicyStore for PolicyEngine<E, KS>
where
    E: aranya_crypto::Engine,
{
    type Policy = VmPolicy<E>;
    type Effect = VmEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, PolicyError> {
        match policy.first() {
            Some(id) => Ok(PolicyId::new(*id as usize)),
            None => Err(PolicyError::Panic),
        }
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, PolicyError> {
        Ok(&self.policy)
    }
}

impl<E, KS> fmt::Debug for PolicyEngine<E, KS>
where
    E: fmt::Debug,
    KS: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEngine").finish_non_exhaustive()
    }
}

/// Sink for effects.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VecSink<E> {
    /// Effects from executing a policy action.
    pub(crate) effects: Vec<E>,
}

impl<E> VecSink<E> {
    /// Creates a new `VecSink`.
    pub(crate) const fn new() -> Self {
        Self {
            effects: Vec::new(),
        }
    }

    /// Returns the collected effects.
    pub(crate) fn collect<T>(self) -> Result<Vec<T>, <T as TryFrom<E>>::Error>
    where
        T: TryFrom<E>,
    {
        self.effects.into_iter().map(T::try_from).collect()
    }
}

impl<E> Sink<E> for VecSink<E> {
    #[instrument(skip_all)]
    fn begin(&mut self) {}

    #[instrument(skip_all)]
    fn consume(&mut self, effect: E) {
        self.effects.push(effect);
    }

    #[instrument(skip_all)]
    fn rollback(&mut self) {}

    #[instrument(skip_all)]
    fn commit(&mut self) {}
}

/// Sink for graph commands.
/// Collects serialized graph commands into a `Vec` after processing an action.
#[derive(Default)]
pub(crate) struct MsgSink {
    cmds: Vec<Box<[u8]>>,
}

impl MsgSink {
    /// Creates a `MsgSink`.
    pub(crate) const fn new() -> Self {
        Self { cmds: Vec::new() }
    }

    /// Returns the collected commands.
    #[cfg(feature = "afc")]
    pub(crate) fn into_cmds(self) -> Vec<Box<[u8]>> {
        self.cmds
    }
}

impl Sink<&[u8]> for MsgSink {
    #[instrument(skip_all)]
    fn begin(&mut self) {}

    #[instrument(skip_all)]
    fn consume(&mut self, effect: &[u8]) {
        self.cmds.push(effect.into())
    }

    #[instrument(skip_all)]
    fn rollback(&mut self) {}

    #[instrument(skip_all)]
    fn commit(&mut self) {}
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use aranya_crypto::{
        default::{DefaultCipherSuite, DefaultEngine},
        keystore::memstore::MemStore,
        Rng,
    };

    use super::*;

    impl TryClone for MemStore {
        type Error = Infallible;

        fn try_clone(&self) -> Result<Self, Self::Error> {
            Ok(self.clone())
        }
    }

    /// Tests that we can compile and build [`POLICY_SOURCE`].
    #[test]
    fn test_policy_compile() {
        let (eng, _) = DefaultEngine::<_, DefaultCipherSuite>::from_entropy(Rng);
        let store = AranyaStore::new(MemStore::new());
        let device_id = DeviceId::default();
        PolicyEngine::<_, _>::new(POLICY_SOURCE, eng, store, device_id).unwrap();
    }
}
