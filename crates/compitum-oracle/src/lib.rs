//! COMPITUM's compatibility ledger — the durable data asset.
//!
//! # What this crate is for
//!
//! Everything else in COMPITUM can be rebuilt from source in an afternoon. This cannot. A
//! [`Ledger`] accumulates the one thing that takes time and many people to acquire: verified
//! statements about *which binary runs on which machine, and why*.
//!
//! That is the moat. Not the routing algorithm — that is a few hundred lines of pure
//! function — but the corpus of observations that tells a user, before they run anything,
//! whether someone has already answered their question.
//!
//! # The shape of an observation
//!
//! A [`Record`] answers five things:
//!
//! 1. **Which bytes?** — a SHA-256 of the subject, so a record survives renames and joins
//!    with someone else's independent observation of the same release.
//! 2. **What was decided, and why?** — the ABI family, the route, and the required features.
//! 3. **On what machine?** — a [`HostSnapshot`] capturing architecture, page size, and the
//!    exact capability set.
//! 4. **What happened?** — an [`Outcome`], which may be undetermined.
//! 5. **How do we know?** — a [`Provenance`], because a measurement and a prediction
//!    deserve different weight.
//!
//! # Why a record can be reused
//!
//! The point of capturing all five is transferability. [`Record::applies_to`] decides
//! whether a past observation answers a present question:
//!
//! * A **success** on a host that had every required feature transfers to any host with a
//!   superset of those features and the same architecture and page size.
//! * A **failure** caused by a missing capability transfers downward: a host missing the
//!   same feature will fail identically, which is itself a useful prediction.
//! * A **prediction** never outranks a **measurement**.
//! * An **undetermined** outcome answers nothing at all.
//!
//! # Storage
//!
//! JSON Lines, append-only, human-readable. A ledger must still be readable by `grep` in ten
//! years on a machine running none of today's software, and it must be mergeable between
//! contributors with `git merge`. A binary database is neither.
//!
//! # Failure policy
//!
//! An unreadable line is skipped and counted, never fatal. A ledger accumulates records
//! written by older and newer versions of the tool; refusing to open it because one line
//! came from a future schema would defeat its entire purpose.
//!
//! # Example
//!
//! ```
//! use compitum_oracle::{HostSnapshot, Ledger, Outcome, Provenance, Record};
//!
//! let snapshot = HostSnapshot {
//!     arch: "aarch64".to_owned(),
//!     page_size: 4096,
//!     cpu_count: 8,
//!     kernel: "6.1.0".to_owned(),
//!     features: vec!["fp".to_owned(), "asimd".to_owned()],
//! };
//!
//! let record = Record::statically_analysed(
//!     compitum_digest::sha256(b"app.exe"),
//!     7,
//!     Some("app.exe".to_owned()),
//!     "arm64",
//!     "native",
//!     false,
//!     true,
//!     1000,
//!     vec!["fp".to_owned()],
//!     snapshot.clone(),
//!     1_700_000_000,
//! ).with_outcome(Outcome::Success, Provenance::ObservedExecution, None);
//!
//! let mut ledger = Ledger::in_memory();
//! ledger.record(record).expect("stored");
//! assert_eq!(ledger.determined_outcomes(), 1);
//! assert_eq!(ledger.applicable_to(&snapshot).len(), 1);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ledger;
pub mod record;

pub use ledger::{default_path, Ledger, LedgerError, LoadStats, RecordAction};
pub use record::{
    identify, HostSnapshot, Outcome, Provenance, Record, RECORD_SCHEMA_VERSION,
};
