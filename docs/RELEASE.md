# Release procedure

This document exists because **a rejected publish permanently consumes a version number**.
crates.io does not allow a version to be reused, so a mistake cannot be undone — only worked
around by bumping. For a family of eight inter-dependent crates that is worse than it sounds:
a partial success leaves some crates at one version and the rest at another, and nothing in the
toolchain will tell you that a mismatch exists.

Everything below is mechanical, and the mechanical parts are automated in
`tools/preflight.py`.

---

## The short version

```console
$ python3 tools/preflight.py
$ cargo publish -p compitum-digest
#   wait for it to appear: https://crates.io/crates/compitum-digest
$ cargo publish -p compitum-json
#   ... and so on, in the order preflight printed
```

If preflight exits non-zero, **do not publish**. It is checking exactly the things a registry
rejects.

---

## Why the order matters, and what it is

A registry cannot resolve a dependency that does not exist yet. So a crate whose dependency is
not live cannot be packaged, let alone published. The order is derived from the real dependency
graph rather than written down, because a hand-maintained list drifts the moment a dependency is
added:

```
1. compitum-digest      no workspace dependencies
2. compitum-json        no workspace dependencies
3. compitum-i18n        requires compitum-json
4. compitum-isa         requires compitum-json
5. compitum-pe          requires compitum-isa, compitum-json
6. compitum-router      requires compitum-isa, compitum-json, compitum-pe
7. compitum-oracle      requires compitum-digest, compitum-isa, compitum-json,
                        compitum-pe, compitum-router
8. compitum-cli         requires everything above
```

`compitum-digest` and `compitum-json` have no internal dependencies, so they can go first in
either order. Everything after them must wait.

---

## What preflight checks, and why each one matters

| Check | Why |
|---|---|
| **The working tree is clean** | A published version must correspond to a commit. Otherwise the release cannot be reproduced, and a bug report against `0.1.0` cannot be checked out. |
| **Every crate has `description`, `license`, `repository`, a README that exists** | Each missing field is a hard rejection. |
| **Keywords and categories are present** | Not a rejection, but without them nobody can find the crate in a search. A published-but-unfindable crate is a wasted version number. |
| **No path dependency lacks a version** | A registry cannot resolve a path. This is the single most common packaging failure. |
| **The dependency graph is acyclic** | A cycle means no publish order exists at all, and it is far cheaper to learn that here than after publishing the first three crates. |
| **Every crate packages independently** | A crate blocked *only* by an unpublished dependency is expected in a fresh family and reported as such. A crate that fails for any **other** reason is a real defect. |
| **The version is not already on the registry** | The most expensive mistake, because it is the one that cannot be undone. |
| **The test suite passes** | A registry release is the worst possible place to discover a broken build. |

---

## Version numbering

The whole family is versioned **in lockstep**: `[workspace.package] version` in the root
`Cargo.toml` is the single source of truth, and every crate inherits it via `version.workspace = true`.

That is deliberate. Crates in this family are not independently useful — `compitum-router`
without `compitum-pe` does nothing — so independent versioning would create a compatibility
matrix nobody would maintain, and users would have to reason about which combinations work.

**What to bump, and when:**

| Change | Bump |
|---|---|
| A bug fix, documentation, an internal refactor | patch |
| A new route, a new reason code, a new CLI flag | minor |
| Removing or renaming a route, a reason code, or a JSON key | **major** |

### The protocol-stability rule

Some values are **protocol**, not API: route identifiers (`fex_partial`), reason codes
(`isa_features_missing`), JSON keys (`subject_sha256`), and schema version numbers. They appear
in stored Oracle records and in other people's CI configuration.

Changing any of them is a **breaking** change regardless of how small it looks in the diff,
because a record written by an older version must remain readable. If a protocol value must
change, add the new one and keep reading the old, then remove the old one a major version later.

---

## After publishing

1. **Tag the commit.** The tag is what makes a release findable later:

   ```console
   $ git tag -a v0.1.0 -m "v0.1.0"
   $ git push origin v0.1.0
   ```

2. **Verify the crates are live and complete.** A crate that published its manifest but not its
   README looks broken on its page:

   ```console
   $ for c in compitum-digest compitum-json compitum-i18n compitum-isa \
              compitum-pe compitum-router compitum-oracle compitum-cli; do
       printf '%-18s ' "$c"
       curl -s "https://crates.io/api/v1/crates/$c" | grep -o '"max_version":"[^"]*"' | head -1
     done
   ```

3. **Install and run it**, which is the only check that exercises what a user actually does:

   ```console
   $ cargo install compitum-cli
   $ compitum host
   $ compitum verify ./some-binary.exe
   ```

4. **Record the release** in the roadmap's proof-of-work log, with the version and the date.
   A release that is not recorded cannot be reasoned about later.

---

## If something goes wrong

| Situation | Response |
|---|---|
| **Preflight fails** | Fix it. That is the whole point of preflight. |
| **A crate published but is broken** | `cargo yank --version 0.1.0 -p <crate>`. Yanking does not delete the version; it removes it from new dependency resolution while leaving existing lockfiles working. Publish a fixed patch version. |
| **The README or metadata is wrong** | Metadata cannot be edited in place. Fix it and publish a patch version. This is why preflight checks metadata. |
| **A crate was published at the wrong version** | Yank it and publish the correct one. The consumed version number is gone permanently. |
| **A mid-family failure** | Complete the remaining crates at the *same* version if they are compatible. Do not bump only the tail; that is what creates a version mismatch nobody can see. |

### On yanking

Yanking is the correct tool and it is frequently misunderstood. It does **not** delete anything
and it does not break existing users. It signals "do not select this version for new
resolutions". A yank plus a patch release is the standard remedy, and it is not a sign of
failure — shipping a version that cannot be fixed is.

---

## What is deliberately manual

- **Publishing itself.** A workflow that can publish by accident will eventually publish by
  accident. The preflight is automated; the irreversible step is not.
- **The version bump.** A human deciding that a change is breaking is a judgement call, and
  automating it would produce confident wrong answers in both directions.
- **The tag.** Tags are cheap and should be created deliberately, against a commit that has
  been verified on the registry rather than one that is merely intended.
