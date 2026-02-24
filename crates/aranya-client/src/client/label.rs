use std::vec;

use aranya_daemon_api::{self as api};
use aranya_id::custom_id;
use aranya_policy_text::Text;

use crate::{
    client::DeviceId,
    util::{impl_vec_into_iter_wrapper, ApiConv as _, ApiId},
};

custom_id! {
    /// An AFC label ID.
    pub struct LabelId;
}
impl ApiId<api::LabelId> for LabelId {}

/// A label.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
pub struct Label {
    /// Uniquely identifies the label.
    pub id: LabelId,
    /// The human-readable label name.
    pub name: Text,
    /// The device that created the label.
    pub author_id: DeviceId,
}

impl Label {
    pub(crate) fn from_api(v: api::Label) -> Self {
        Self {
            id: LabelId::from_api(v.id),
            name: v.name,
            author_id: DeviceId::from_api(v.author_id),
        }
    }
}

/// List of labels.
#[derive(Clone, Debug)]
pub struct Labels {
    pub(super) labels: Box<[Label]>,
}

impl Labels {
    /// Returns an iterator over the labels.
    pub fn iter(&self) -> impl Iterator<Item = &Label> {
        self.labels.iter()
    }

    #[doc(hidden)]
    pub fn __data(&self) -> &[Label] {
        &self.labels
    }

    #[doc(hidden)]
    pub fn __into_data(self) -> Box<[Label]> {
        self.labels
    }
}

impl IntoIterator for Labels {
    type Item = Label;
    type IntoIter = IntoIterLabels;

    fn into_iter(self) -> Self::IntoIter {
        IntoIterLabels(self.labels.into_vec().into_iter())
    }
}

/// An owning iterator over [`Label`]s.
#[derive(Clone, Debug)]
pub struct IntoIterLabels(vec::IntoIter<Label>);

impl_vec_into_iter_wrapper!(IntoIterLabels for Label);
