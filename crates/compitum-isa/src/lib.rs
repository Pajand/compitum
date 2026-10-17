//! The ARM64 instruction-set vocabulary, host capability oracle, and requirement model.
//!
//! This crate answers the second half of `COMPITUM`'s central question. The companion
//! crate `compitum-pe` reads a binary and produces a set of [`Requirement`]s; this crate
//! reads the machine and produces a [`HostProfile`]. The router compares them.
//!
//! # Modules
//!
//! * [`feature`] — the ARM64 feature vocabulary ([`IsaFeature`], [`FeatureSet`]).
//! * [`host`] — probing the running machine ([`HostProfile`]).
//! * [`requirement`] — provenance-aware statements about what a binary needs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod feature;
pub mod host;
pub mod requirement;

pub use feature::{FeatureSet, IsaFeature};
pub use host::HostProfile;
pub use requirement::{Confidence, Requirement, RequirementSource};
