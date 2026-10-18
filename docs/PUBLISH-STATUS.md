# Publication status

**As of:** 2026-10-18
**Verdict:** the name is claimed in every namespace that matters. One optional purchase
remains (the domain), and one technical task is unfinished (ARM64EC execution).

---

## What is claimed

| Namespace | Value | Verified |
|---|---|---|
| **crates.io** | `compitum-digest`, `compitum-json`, `compitum-i18n`, `compitum-isa`, `compitum-pe`, `compitum-router`, `compitum-oracle`, `compitum-cli` — all `0.1.0` | ✅ **8 of 8 live**, every one pointing at the organisation |
| **npm** | `compitum@0.0.3` | ✅ `latest`, metadata points at the organisation |
| **PyPI** | `compitum 0.1.0` | ✅ wheel and sdist published |
| **GitHub organisation** | `compitum-dev` | ✅ `Pajand` is `admin` |
| **GitHub repository** | `compitum-dev/compitum` | ✅ 85 files, full commit history |
| **GHCR** | `ghcr.io/compitum-dev/compitum` | ✅ automatic, inherits the org |
| **Domain** | `compitum.dev` | ⬜ **not registered** — requires a purchase decision |

The npm package was published three times to correct its metadata: `0.0.1` pointed at a
personal account path, `0.0.3` points at the organisation.

---

## How the publish order was determined, and why it mattered

`tools/publish_order.py` derives the sequence from the real dependency graph:

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

A registry cannot resolve a dependency that does not exist yet, and **a rejected publish
permanently consumes the version number**. The order is therefore load-bearing, which is why
it is computed rather than written down.

---

## What the publish run actually encountered

Three obstacles, all diagnosable and all now understood.

### 1. crates.io requires a verified email address

The first attempt authenticated successfully and was then refused:

```text
A verified email address is required to publish crates to crates.io.
Visit https://crates.io/settings/profile to set and verify your email address.
```

That is the token working correctly and the registry applying an anti-spam rule. Nothing about
the credential needed changing.

### 2. crates.io rate-limits new crates

After six successful publishes the registry answered:

```text
429 Too Many Requests: You have published too many new crates in a short period of time.
Please try again after Sun, 18 Oct 2026 14:29:23 GMT
```

A deliberate anti-abuse limit, not a defect. The remaining crates were retried after the
stated time and published.

### 3. A failure-detection bug in my own script

An earlier version of the publish script treated `compitum-digest` as **failed** when it had in
fact already been published. crates.io words that case as:

```text
crate version `0.1.0` is already uploaded
```

while the script matched on `"already exists"` / `"previously published"`. A success was
therefore read as a failure and the sequence aborted after the first crate.

This is the same defect shape as the others found in this project: a check reporting something
other than what actually happened. **Match the server's real wording, not what you assumed it
would be.**

---

## Certification

- Published entirely through automation, with no manual step except the email verification.
- Every crate's `repository` field was verified to point at `compitum-dev/compitum` after
  publication, so the registry page links to the right place.
- The repository's own CI was green on every commit that was published.

---

## Still open

**The domain `compitum.dev` is not registered.** It is free (verified against the registry's
RDAP), and it requires a payment decision. Everything in the name scheme works without it,
except the final transition from `compitum.dev@gmail.com` to `hello@compitum.dev`.

**ARM64EC execution is not yet proven.** Phase 1 tasks 1.1, 1.2 and 1.4 are met — native
execution, prediction-versus-observation, and NT syscall translation. Task 1.3 needs Wine 10.0
or later, and the probe workflow that establishes whether a build is necessary is under
development. See `docs/PHASE1-FEASIBILITY.md`.

---

## Credentials

All three are stored in the encrypted vault and were exercised against the real service:

| Vault id | Test performed | Result |
|---|---|---|
| `crates-io` | eight real publishes | ✅ |
| `pypi` | a real `twine upload` | ✅ |
| `npm` | three real publishes | ✅ |
| `compitum-dev-github` | transfer, and repository reads | ✅ |

A method note on the PyPI test, because it cost time to work out: a **valid** upload token
POSTed with a junk body returns `400` describing the *payload* problem, while an **invalid**
token returns `403` or a `400` naming the *authentication token*. Reading which of those
appeared is what distinguishes valid from invalid; a bare status code cannot.
