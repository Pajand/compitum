//! COMPITUM's routing engine — layer 3, and the decision the product exists to make.
//!
//! # The question
//!
//! Given a parsed binary and a probed host, **which execution path is correct, and why?**
//!
//! The answer is a [`Plan`]: a [`Route`], the [`Reasons`] that justify it, and a
//! [`Confidence`] that is honest about how good the evidence was.
//!
//! # The decision, at a glance
//!
//! | Image family | Host has required ISA features? | Required backend present? | Route |
//! |---|---|---|---|
//! | pure ARM64 | yes | — | [`Route::Native`] |
//! | ARM64X (fat) | yes | — | [`Route::PickNativeSlice`] |
//! | ARM64EC (hybrid) | yes | FEX | [`Route::FexPartial`] |
//! | x86-64 | yes | Box64 or FEX | [`Route::Box64Full`] / [`Route::FexFull`] |
//! | x86 (32-bit) | yes | Box86 | [`Route::Wow64`] |
//! | anything else | — | — | [`Route::Refused`] |
//!
//! # The one row that matters most
//!
//! An ARM64EC image contains both AArch64 and x86-64 code. A tool that knows only "this is
//! a hybrid, therefore emulate it" sends it to a full translator and translates code that
//! was already native. Sending it to [`Route::FexPartial`] instead keeps the AArch64
//! majority at hardware speed — 70-90% of native throughput instead of 30-60%. That
//! difference is the product.
//!
//! # Design constraints
//!
//! * **Purity.** [`decide`] performs no I/O and consults no ambient state, so a decision can
//!   be reproduced exactly from a stored Oracle record.
//! * **No execution.** This crate decides; it never loads, maps or runs an image.
//! * **Honest refusals.** When no correct route exists, the reason names the specific
//!   obstacle, including which CPU features are missing.
//!
//! # Example
//!
//! ```
//! use compitum_isa::{FeatureSet, HostProfile, IsaFeature};
//! use compitum_pe::{parse, pe_fixture};
//! use compitum_router::{decide, BackendSet, Request, Route};
//!
//! // Fixture constants live under the fixture module, keeping them distinct from the
//! // analysed `Machine` type at the crate root.
//! let bytes = pe_fixture::synthetic(
//!     pe_fixture::machine::ARM64,
//!     pe_fixture::subsystem::CONSOLE,
//!     false,
//! );
//! let image = parse(&bytes).unwrap();
//!
//! // A host implementing exactly the features the image needs.
//! let host = HostProfile::synthetic(
//!     "aarch64",
//!     4096,
//!     8,
//!     FeatureSet::new().with(IsaFeature::Fp).with(IsaFeature::Asimd),
//! );
//!
//! let plan = decide(&Request::new(image, host, BackendSet::all()));
//! assert_eq!(plan.route, Route::Native);
//! assert!(plan.is_fully_native());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The crate README is included as documentation, which makes every Rust example in it a
// compiled doctest. An example that is not compiled is an example that silently rots, and a
// wrong example on a crate page is worse than no example at all.
#![doc = include_str!("../README.md")]

pub mod discovery;
pub mod engine;
pub mod plan;
pub mod reason;
pub mod route;

pub use discovery::{discover, BackendProbe, Discovery, Found};
pub use engine::{decide, Request, Subject};
pub use plan::{Plan, SCHEMA_VERSION};
pub use reason::{Reason, ReasonCode, Reasons, Severity};
pub use route::{Backend, BackendSet, Route, ThroughputExpectation};
