#![allow(missing_docs)]

use std::fmt;

use anyhow::{Context, Result};
use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::keystore::{KeyStore, fs_keystore::Store};
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::ffi::FfiModule;
use aranya_runtime::{
    Sink,
    vm_policy::{FfiSet, SealCtx, VmPolicyStore},
};
use tracing::instrument;

use crate::{
    keystore::AranyaStore,
    policy::{ChanOp, Perm},
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

/// Display implementation for [`Perm`]
impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Perm::{self:?}")
    }
}

pub(crate) fn create_policy_store<CE, KS>(
    eng: CE,
    keystore: AranyaStore<KS>,
    seal_ctx: SealCtx<CE>,
) -> Result<VmPolicyStore<CE>>
where
    CE: aranya_crypto::Engine,
    KS: KeyStore + TryClone + Send + Sync + 'static,
{
    // select which FFI modules to use.
    let ffis = FfiSet::new()
        .with(AfcFfi::new(keystore.try_clone()?))?
        .with(DeviceFfi::new(seal_ctx.author))?
        .with(IdamFfi::new(keystore))?
        .with(PerspectiveFfi)?;

    Ok(VmPolicyStore::new(eng, ffis, seal_ctx))
}

pub(crate) fn compile_policy(policy_doc: &str) -> Result<Vec<u8>> {
    let ast = parse_policy_document(policy_doc).context("unable to parse policy document")?;
    let module = Compiler::new(&ast)
        .flavors(&aranya_runtime::vm_policy::FLAVORS)
        .ffi_modules(&[
            AfcFfi::<Store>::SCHEMA,
            DeviceFfi::SCHEMA,
            IdamFfi::<Store>::SCHEMA,
            PerspectiveFfi::SCHEMA,
        ])
        .compile()
        .context("should be able to compile policy")?;
    Ok(module.write_to_vec()?)
}

/// Sink for effects.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VecSink<Eff> {
    /// Effects from executing a policy action.
    pub(crate) effects: Vec<Eff>,
}

impl<Eff> VecSink<Eff> {
    /// Creates a new `VecSink`.
    pub(crate) const fn new() -> Self {
        Self {
            effects: Vec::new(),
        }
    }

    /// Returns the collected effects.
    pub(crate) fn collect<T>(self) -> Result<Vec<T>, <T as TryFrom<Eff>>::Error>
    where
        T: TryFrom<Eff>,
    {
        self.effects.into_iter().map(T::try_from).collect()
    }
}

impl<Eff> Sink<Eff> for VecSink<Eff> {
    #[instrument(skip_all)]
    fn begin(&mut self) {}

    #[instrument(skip_all)]
    fn consume(&mut self, effect: Eff) {
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
        DeviceId, Rng, SigningKey,
        default::{DefaultCipherSuite, DefaultEngine},
        id::IdExt as _,
        keystore::memstore::MemStore,
    };
    use aranya_runtime::{PolicyStore, VmPolicy};

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
        let keystore = AranyaStore::new(MemStore::new());
        let seal_ctx = SealCtx {
            author: DeviceId::random(Rng),
            key: SigningKey::new(Rng),
        };
        let mut policy_store = create_policy_store(eng, keystore, seal_ctx).unwrap();
        let policy = compile_policy(POLICY_SOURCE).unwrap();
        let id = policy_store.add_policy(&policy).unwrap();
        let _: &VmPolicy<_> = policy_store.get_policy(id).unwrap();
    }
}
