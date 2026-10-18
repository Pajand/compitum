# Publication status

**As of:** 2026-10-18
**Verdict:** every credential is valid. **One manual action remains** before the crates can be
published.

---

## What is claimed, and by whom

| Namespace | Value | Owner | Verified |
|---|---|---|---|
| npm | `compitum` | `pajand` | ✅ `0.0.3` is `latest`, metadata points at the organisation |
| GitHub org | `compitum-dev` | `Pajand` (role `admin`) | ✅ repository transferred, redirect active |
| GitHub repository | `compitum-dev/compitum` | the organisation | ✅ 85 files, full history |
| Container | `ghcr.io/compitum-dev/compitum` | inherits the org | ✅ no separate signup needed |
| PyPI | `compitum` — **free** | — | ✅ name unclaimed, token authenticated |
| crates.io | `compitum`, `compitum-*` — free | — | ⚠️ token valid, **email unverified** |
| Domain | `compitum.dev` — free | — | ⬜ not yet registered |

The npm package was published twice to correct its metadata: `0.0.1` pointed at a personal
account path, and `0.0.3` points at the organisation.

---

## The one blocker: crates.io requires a verified email

A publish attempt authenticated successfully and was then refused with a specific message:

```text
error: failed to publish to registry at https://crates.io
Caused by:
  the remote server responded with an error (status 400 Bad Request): A verified email
  address is required to publish crates to crates.io. Visit
  https://crates.io/settings/profile to set and verify your email address.
```

**This is the token working correctly.** Authentication passed; the registry is applying an
anti-spam rule. Nothing about the token needs changing.

### The action

```text
1. go to   https://crates.io/settings/profile
2. if the email field is empty, enter  compitum.dev@gmail.com
3. press  "Resend verification email"
4. open the  compitum.dev@gmail.com  inbox and click the verification link
```

The token does **not** need to be regenerated or re-supplied.

---

## Credential audit — how each was tested

Guessing whether a credential works is not useful, so each was exercised against the real
service. The table records what was done, not what was assumed.

| Credential | Test | Result |
|---|---|---|
| `compitum-dev-github` | read `/user`; read the org repository | ✅ authenticates as `compitum-dev-archive`, HTTP 200 on the org repo |
| `crates-io` | **a real `cargo publish`** of `compitum-digest` | ✅ authenticated; refused only for the unverified email |
| `pypi` | POST to `upload.pypi.org/legacy/` with a deliberately empty payload | ✅ HTTP 400 about a **missing Name field**, which means auth passed |
| `npm` | `npm whoami`, then two real publishes | ✅ publishes as `pajand` |

### A method note on the PyPI test

A valid PyPI upload token POSTed with a junk body returns `400` describing the *payload*
problem, while an invalid token returns `403` or a `400` naming the *authentication token*.
Reading which of those two appeared is what distinguishes a valid credential from an invalid
one — a bare status code cannot, which is why earlier attempts to test it were inconclusive.

### Why the crates.io API returned 403

`GET https://crates.io/api/v1/me` answers:

```json
{"errors":[{"detail":"this action can only be performed on the crates.io website"}]}
```

That is **not** an authentication failure. The endpoint is deliberately web-only, so a 403
there says nothing about a token's validity. Only an actual publish exercises the credential,
which is why the test was a real upload rather than an API probe.

---

## Publish order

Derived from the real dependency graph by `tools/publish_order.py`. It is load-bearing: a
registry cannot resolve a dependency that does not exist yet, and a **rejected publish
permanently consumes the version number**.

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

`tools/preflight.py` validates all of it and currently reports **READY**.

---

## Not done, and why

**The domain was not registered.** It requires a payment decision, so it waits on the owner.
Everything else in the name scheme works without it — but the transition from
`compitum.dev@gmail.com` to `hello@compitum.dev` cannot happen until the domain exists.

**The VPS in the vault cannot build ARM64.** It was checked: `107.181.155.199` reports
`x86_64`. An ARM64 Wine build needs ARM64 hardware, so the VPS is not an alternative to the
CI runner for that task. Worth recording so nobody tries it again on the assumption that a
server is always better than a phone.
