#![allow(missing_docs)]

use std::{fmt, marker::PhantomData, str::FromStr};

use anyhow::{Context, Result, anyhow};
use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::{UserId, keystore::fs_keystore::Store};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{Machine, ffi::FfiModule};
use aranya_runtime::{
    FfiCallable, Sink, VmEffect, VmPolicy,
    engine::{Engine, EngineError, PolicyId},
};
use tracing::instrument;

use super::policy::ChanOp;
use crate::policy::Role;

/// Policy loaded from policy.md file.
pub const TEST_POLICY_1: &str = include_str!("./policy.md");

/// Converts [`ChanOp`] to string.
impl FromStr for ChanOp {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ChanOp::ReadOnly" => Ok(Self::ReadOnly),
            "ChanOp::WriteOnly" => Ok(Self::WriteOnly),
            "ChanOp::ReadWrite" => Ok(Self::ReadWrite),
            _ => Err(anyhow!("unknown `ChanOp`: {s}")),
        }
    }
}

/// Display implementation for [`ChanOp`]
impl fmt::Display for ChanOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChanOp::{:?}", self)
    }
}

/// Engine using policy from [`policy.md`].
pub struct PolicyEngine<E, KS> {
    /// The underlying policy.
    pub policy: VmPolicy<E>,
    _eng: PhantomData<E>,
    _ks: PhantomData<KS>,
}

impl<E> PolicyEngine<E, Store>
where
    E: aranya_crypto::Engine,
{
    /// Creates a `PolicyEngine` from a policy document.
    pub fn new(policy_doc: &str, eng: E, store: Store, user_id: UserId) -> Result<Self> {
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

        // select which FFI moddules to use.
        let ffis: Vec<Box<dyn FfiCallable<E> + Send + 'static>> = vec![
            Box::from(AfcFfi::new(store.try_clone()?)),
            Box::from(CryptoFfi::new(store.try_clone()?)),
            Box::from(DeviceFfi::new(user_id)),
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

impl<E, KS> Engine for PolicyEngine<E, KS>
where
    E: aranya_crypto::Engine,
{
    type Policy = VmPolicy<E>;
    type Effect = VmEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        match policy.first() {
            Some(id) => Ok(PolicyId::new(*id as usize)),
            None => Err(EngineError::Panic),
        }
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

/// Converts policy [`Role`] to string.
impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner => f.write_str("Owner"),
            Self::Admin => f.write_str("Admin"),
            Self::Operator => f.write_str("Operator"),
            Self::Member => f.write_str("Member"),
        }
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
    pub const fn new() -> Self {
        Self {
            effects: Vec::new(),
        }
    }

    /// Returns the collected effects.
    pub fn collect<T>(self) -> Result<Vec<T>, <T as TryFrom<E>>::Error>
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
pub struct MsgSink {
    cmds: Vec<Box<[u8]>>,
}

impl MsgSink {
    /// Creates a `MsgSink`.
    pub const fn new() -> Self {
        Self { cmds: Vec::new() }
    }

    /// Returns the collected commands.
    pub fn into_cmds(self) -> Vec<Box<[u8]>> {
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
