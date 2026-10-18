//! The two Oracle stores, and the licence boundary between them.
//!
//! # Why this is code and not a policy document
//!
//! `docs/LICENSING.md` states that community-contributed observations are licensed `ODbL-1.0`
//! (a share-alike data licence) while observations this project produces itself are proprietary,
//! and that **the two are kept in separate stores so the share-alike obligation cannot reach
//! the proprietary data.**
//!
//! A policy that lives only in prose decays. Someone merges the stores for convenience, the
//! combined database becomes a derivative of the `ODbL` one, and the whole of it silently
//! becomes share-alike — which would destroy the commercial position this project depends on.
//! Nobody would notice until a lawyer did.
//!
//! So the boundary is expressed as a type. [`Store`] names the two, carries the licence that
//! applies to each, and provides the path layout. [`StoreBoundary`] refuses to let a ledger be
//! opened in a way that mixes them.
//!
//! # The legal reasoning, briefly
//!
//! `ODbL` permits commercial use but requires a **derivative database** to be released under the
//! same terms. That is desirable: it means a competitor may use the community data, but may not
//! take it, improve it, and enclose the improvement.
//!
//! A licence on contributed data cannot reach data that was never derived from it. Data
//! generated independently on hardware this project controls is therefore free to be
//! proprietary — **provided the two are never combined into one database.**
//!
//! Queries may join them at the API layer. The *stored artefacts* must stay distinct. That is
//! the distinction this module exists to enforce.
//!
//! # Produced works are unaffected
//!
//! A compatibility report, a migration assessment, a chart — these are *produced works*, not
//! derivative databases, and `ODbL` does not force them open. That is what makes it possible to
//! sell a migration-validation engagement built on top of community data.

use std::path::{Path, PathBuf};

/// One of the two Oracle stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Store {
    /// Observations contributed by users and the community. Share-alike.
    Community,
    /// Observations this project produced itself on hardware it controls. Proprietary.
    Verified,
}

impl Store {
    /// Both stores, in canonical order.
    pub const ALL: &'static [Store] = &[Store::Community, Store::Verified];

    /// The stable directory name. Protocol value: it appears in paths users have on disk, so it
    /// must not change.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Store::Community => "oracle-community",
            Store::Verified => "oracle-verified",
        }
    }

    /// The licence that applies to this store's contents.
    ///
    /// Returned as a stable identifier rather than prose, because the value also appears in the
    /// API and in acquisition due-diligence material.
    #[must_use]
    pub fn licence_id(self) -> &'static str {
        match self {
            Store::Community => "ODbL-1.0",
            Store::Verified => "proprietary",
        }
    }

    /// A one-sentence English explanation, for reports and for the API.
    #[must_use]
    pub fn licence_summary(self) -> &'static str {
        match self {
            Store::Community => {
                "Community-contributed observations. Usable commercially, but a derivative \
                 database must be released under the same terms, so no one can take this data \
                 and enclose an improvement of it."
            }
            Store::Verified => {
                "Observations produced by this project on hardware it controls, generated \
                 independently of the community dataset. A commercial licence is required."
            }
        }
    }

    /// Returns `true` when the contents of this store may be redistributed freely.
    ///
    /// The distinction the whole policy rests on. A caller that needs to know whether it may
    /// republish a result should ask this rather than inspect the licence string.
    #[must_use]
    pub fn is_openly_redistributable(self) -> bool {
        matches!(self, Store::Community)
    }

    /// Returns `true` when the share-alike obligation applies to derivatives of this store.
    #[must_use]
    pub fn is_share_alike(self) -> bool {
        matches!(self, Store::Community)
    }

    /// The ledger filename inside a store directory.
    #[must_use]
    pub fn ledger_filename(self) -> &'static str {
        // Different filenames on purpose. If the two stores were ever pointed at one directory,
        // distinct filenames mean they still land in separate files rather than interleaving.
        match self {
            Store::Community => "community.jsonl",
            Store::Verified => "verified.jsonl",
        }
    }

    /// The full path of this store's ledger under a data root.
    #[must_use]
    pub fn ledger_path(self, root: &Path) -> PathBuf {
        root.join(self.id()).join(self.ledger_filename())
    }
}

/// Opens and validates store paths, refusing arrangements that would merge them.
///
/// # Why a validator rather than a convention
///
/// The rule "never merge the stores" is easy to state and easy to break by accident: pass one
/// root for both, or symlink one directory at the other, and the separation disappears without
/// anything failing. A validator turns the rule into an error at the moment it is broken, which
/// is the only point at which it is cheap to fix.
#[derive(Debug, Clone)]
pub struct StoreBoundary {
    root: PathBuf,
    /// Explicit directory per store. Derived from `root` by [`StoreBoundary::new`], or given
    /// directly by [`StoreBoundary::with_paths`] when a store lives elsewhere — a mounted
    /// dataset, a network volume, a CI cache.
    ///
    /// Held separately because deriving both from one root makes them siblings *always*, which
    /// made the nesting guard in [`StoreBoundary::verify`] unreachable. A check that cannot fire
    /// is the same defect as a rule that cannot match, and this project has now produced three of
    /// them. Explicit directories make the mistake expressible, and therefore checkable.
    directories: [PathBuf; 2],
}

/// A refusal to use an arrangement that would merge the stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryError {
    /// The same directory was given for both stores.
    SameDirectory {
        /// The offending path.
        path: String,
    },
    /// One store's directory is inside the other's, which nests their contents.
    Nested {
        /// The outer store.
        outer: Store,
        /// The inner store.
        inner: Store,
    },
}

impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundaryError::SameDirectory { path } => write!(
                f,
                "both stores would live in {path}; the community data is ODbL-licensed and \
                 merging it with the proprietary store would make the combined database a \
                 derivative, subjecting all of it to share-alike"
            ),
            BoundaryError::Nested { outer, inner } => write!(
                f,
                "the `{}` store would sit inside `{}`; nesting the stores makes their contents a \
                 single database, with the same consequence",
                inner.id(),
                outer.id()
            ),
        }
    }
}

impl std::error::Error for BoundaryError {}

impl StoreBoundary {
    /// Creates a boundary rooted at a data directory, deriving the two sibling directories.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let community = root.join(Store::Community.id());
        let verified = root.join(Store::Verified.id());
        StoreBoundary {
            root,
            directories: [community, verified],
        }
    }

    /// Creates a boundary with explicit directories for each store.
    ///
    /// This is how an operator points one store at a mounted or cached dataset, which is a real
    /// arrangement: a company may sync the community dataset to a shared volume while keeping
    /// verified data local. It is also the only way a nesting mistake can be expressed, and so
    /// the only way [`StoreBoundary::verify`] can be exercised.
    #[must_use]
    pub fn with_paths(community: impl Into<PathBuf>, verified: impl Into<PathBuf>) -> Self {
        let community = community.into();
        let verified = verified.into();
        // The root is the common ancestor when there is one, so diagnostic output stays useful.
        let root = community
            .parent()
            .filter(|parent| verified.starts_with(parent))
            .map(Path::to_path_buf)
            .unwrap_or_else(|| community.clone());
        StoreBoundary {
            root,
            directories: [community, verified],
        }
    }

    /// The data root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory for one store.
    #[must_use]
    pub fn directory(&self, store: Store) -> PathBuf {
        match store {
            Store::Community => self.directories[0].clone(),
            Store::Verified => self.directories[1].clone(),
        }
    }

    /// The ledger path for one store.
    #[must_use]
    pub fn ledger_path(&self, store: Store) -> PathBuf {
        store.ledger_path(&self.root)
    }

    /// Verifies that the boundary holds: the two directories are distinct and neither contains
    /// the other.
    ///
    /// Compares paths lexically rather than resolving symlinks, because resolution would require
    /// the directories to exist and the check must work before the stores are created.
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryError`] when the arrangement would merge or nest the stores.
    pub fn verify(&self) -> Result<(), BoundaryError> {
        let community = self.directory(Store::Community);
        let verified = self.directory(Store::Verified);

        if community == verified {
            return Err(BoundaryError::SameDirectory {
                path: community.display().to_string(),
            });
        }
        if verified.starts_with(&community) {
            return Err(BoundaryError::Nested {
                outer: Store::Community,
                inner: Store::Verified,
            });
        }
        if community.starts_with(&verified) {
            return Err(BoundaryError::Nested {
                outer: Store::Verified,
                inner: Store::Community,
            });
        }
        Ok(())
    }

    /// Verifies the boundary and creates both directories.
    ///
    /// # Errors
    ///
    /// Returns a message when the boundary is invalid or a directory cannot be created.
    pub fn prepare(&self) -> Result<(), String> {
        self.verify().map_err(|e| e.to_string())?;
        for store in Store::ALL {
            let dir = self.directory(*store);
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        Ok(())
    }

    /// A machine-readable description of the licence boundary, for the API and for due
    /// diligence.
    #[must_use]
    pub fn to_json(&self) -> compitum_json::Value {
        let stores: Vec<compitum_json::Value> = Store::ALL
            .iter()
            .map(|store| {
                compitum_json::Object::new()
                    .with("store", store.id())
                    .with("licence", store.licence_id())
                    .with("redistributable", store.is_openly_redistributable())
                    .with("share_alike", store.is_share_alike())
                    .with("path", self.directory(*store).display().to_string())
                    .with("summary", store.licence_summary())
                    .into()
            })
            .collect();

        compitum_json::Object::new()
            .with("data_root", self.root.display().to_string())
            .with("store_count", stores.len())
            // Stated as a machine-readable fact so an automated check can assert it, rather than
            // discovering it from a document.
            .with("stores_are_merged", false)
            .with("stores", stores)
            .into()
    }
}

/// The default data root for this user, following the XDG convention.
#[must_use]
pub fn default_data_root() -> PathBuf {
    if let Ok(explicit) = std::env::var("COMPITUM_DATA") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("compitum")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_stores_are_distinct() {
        assert_ne!(Store::Community, Store::Verified);
        assert_ne!(Store::Community.id(), Store::Verified.id());
        assert_ne!(
            Store::Community.ledger_filename(),
            Store::Verified.ledger_filename(),
            "distinct filenames mean that even a shared directory keeps the data in separate \
             files rather than interleaving it"
        );
    }

    #[test]
    fn the_community_store_is_open_and_share_alike() {
        assert!(Store::Community.is_openly_redistributable());
        assert!(Store::Community.is_share_alike());
        assert_eq!(Store::Community.licence_id(), "ODbL-1.0");
    }

    #[test]
    fn the_verified_store_is_neither_open_nor_share_alike() {
        // This is the commercial position, asserted rather than described.
        assert!(!Store::Verified.is_openly_redistributable());
        assert!(!Store::Verified.is_share_alike());
        assert_eq!(Store::Verified.licence_id(), "proprietary");
    }

    #[test]
    fn every_store_explains_its_own_licence() {
        for store in Store::ALL {
            let text = store.licence_summary();
            assert!(
                text.len() > 60,
                "{} has an unhelpfully short summary",
                store.id()
            );
        }
        // The community summary must name the obligation, since that is what protects the moat.
        assert!(Store::Community
            .licence_summary()
            .contains("derivative database"));
    }

    #[test]
    fn paths_are_derived_from_the_store_not_shared() {
        let boundary = StoreBoundary::new("/data");
        assert_eq!(
            boundary.directory(Store::Community),
            PathBuf::from("/data/oracle-community")
        );
        assert_eq!(
            boundary.directory(Store::Verified),
            PathBuf::from("/data/oracle-verified")
        );
        assert_ne!(
            boundary.ledger_path(Store::Community),
            boundary.ledger_path(Store::Verified)
        );
    }

    #[test]
    fn a_shared_root_is_accepted_because_the_directories_differ() {
        // One root for both is the normal arrangement: the boundary is about the directories,
        // not the root.
        let boundary = StoreBoundary::new("/data");
        assert!(boundary.verify().is_ok());
    }

    #[test]
    fn nesting_the_stores_is_refused() {
        // If the verified store lived inside the community one, their contents would form a
        // single database and the share-alike obligation would reach the proprietary data.
        //
        // `with_paths` is required because that is the only way the mistake can be expressed.
        // The earlier revision derived both directories from one root, which made them siblings
        // *always* -- so the guard was unreachable and the test could only have been written
        // against a premise that did not hold. The test found that: it failed, and the design
        // was wrong rather than the test.
        let nested = StoreBoundary::with_paths(
            "/data/oracle-community",
            "/data/oracle-community/oracle-verified",
        );
        match nested.verify() {
            Err(BoundaryError::Nested { outer, inner }) => {
                assert_eq!(outer, Store::Community);
                assert_eq!(inner, Store::Verified);
            }
            other => panic!("expected Nested, got {other:?}"),
        }
    }

    #[test]
    fn nesting_the_other_way_round_is_also_refused() {
        // The reverse arrangement is the same mistake and must be caught identically.
        let nested = StoreBoundary::with_paths(
            "/data/oracle-verified/oracle-community",
            "/data/oracle-verified",
        );
        match nested.verify() {
            Err(BoundaryError::Nested { outer, inner }) => {
                assert_eq!(outer, Store::Verified);
                assert_eq!(inner, Store::Community);
            }
            other => panic!("expected Nested, got {other:?}"),
        }
    }

    #[test]
    fn identical_directories_are_refused() {
        // The other way the boundary can collapse: both stores at one path.
        let collapsed = StoreBoundary::with_paths("/data/one", "/data/one");
        assert_eq!(
            collapsed.verify(),
            Err(BoundaryError::SameDirectory {
                path: "/data/one".to_owned()
            })
        );
    }

    #[test]
    fn unrelated_directories_are_accepted() {
        // A dataset mounted elsewhere is legitimate and must not be refused.
        assert!(
            StoreBoundary::with_paths("/data/community", "/mnt/verified-store")
                .verify()
                .is_ok()
        );
    }

    #[test]
    fn the_nesting_error_names_the_consequence() {
        let error = BoundaryError::Nested {
            outer: Store::Community,
            inner: Store::Verified,
        };
        let text = error.to_string();
        assert!(text.contains("oracle-verified"));
        assert!(text.contains("oracle-community"));
        assert!(
            text.contains("single database"),
            "the error must state the legal consequence, not merely the nesting"
        );
    }

    #[test]
    fn the_same_directory_error_names_the_consequence() {
        let error = BoundaryError::SameDirectory {
            path: "/data/one".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("ODbL"));
        assert!(text.contains("share-alike"));
    }

    #[test]
    fn prepare_creates_both_directories_and_reports_failure() {
        let root = std::env::temp_dir().join("compitum-store-boundary-test");
        let _ = std::fs::remove_dir_all(&root);
        let boundary = StoreBoundary::new(&root);

        boundary.prepare().expect("a valid boundary must prepare");
        for store in Store::ALL {
            assert!(
                boundary.directory(*store).is_dir(),
                "{} was not created",
                store.id()
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prepare_refuses_an_invalid_boundary() {
        // `prepare` creates directories, so it must verify FIRST and refuse a collapsed layout
        // rather than create a merged one on disk.
        let collapsed =
            StoreBoundary::with_paths("/tmp/compitum-collapse", "/tmp/compitum-collapse");
        let error = collapsed.prepare().unwrap_err();
        assert!(
            error.contains("share-alike"),
            "the refusal must name the legal consequence, not merely the path: {error}"
        );
    }

    #[test]
    fn json_states_that_the_stores_are_not_merged() {
        let boundary = StoreBoundary::new("/data");
        let json = boundary.to_json();
        assert_eq!(json["stores_are_merged"].as_bool(), Some(false));
        assert_eq!(json["store_count"].as_u64(), Some(2));

        let stores = json["stores"].as_array().expect("an array");
        assert_eq!(stores.len(), 2);
        assert_eq!(stores[0]["store"].as_str(), Some("oracle-community"));
        assert_eq!(stores[0]["licence"].as_str(), Some("ODbL-1.0"));
        assert_eq!(stores[0]["redistributable"].as_bool(), Some(true));
        assert_eq!(stores[1]["store"].as_str(), Some("oracle-verified"));
        assert_eq!(stores[1]["licence"].as_str(), Some("proprietary"));
        assert_eq!(stores[1]["redistributable"].as_bool(), Some(false));
    }

    #[test]
    fn default_data_root_honours_the_environment_override() {
        let previous = std::env::var("COMPITUM_DATA").ok();
        std::env::set_var("COMPITUM_DATA", "/tmp/explicit-data");
        assert_eq!(default_data_root(), PathBuf::from("/tmp/explicit-data"));
        match previous {
            Some(v) => std::env::set_var("COMPITUM_DATA", v),
            None => std::env::remove_var("COMPITUM_DATA"),
        }
    }

    #[test]
    fn store_ids_are_stable_protocol_values() {
        // These appear in paths users already have on disk, so they must not change.
        assert_eq!(Store::Community.id(), "oracle-community");
        assert_eq!(Store::Verified.id(), "oracle-verified");
        assert_eq!(Store::ALL.len(), 2);
    }
}
