# NAMING DECISION RECORD

**Status:** decided, in force
**Date:** 2026-10-18
**Supersedes:** the original working name, rejected after due diligence

---

## 1. THE NAME

> ## COMPITUM

From Latin *compitum*: **a crossroads — the point where roads meet and a direction must
be chosen.** That is literally what this software does: it inspects an ARM64 binary and
decides, with evidence, which execution path is correct.

It is a real classical word rather than an invented brand, which means it is
registrable, pronounceable in every language, and carries no unfortunate meaning.

---

## 2. WHY THE FIRST TWO CANDIDATES WERE REJECTED

Recording the rejections matters as much as recording the choice, because it is the
evidence that the screening was actually done.

| Candidate | Verdict | Evidence |
|---|---|---|
| **TESSERA** | ⛔ rejected | `Tessera Technologies, Inc.` / `Tessera, Inc.` is a semiconductor IP company, formerly NASDAQ:TSRA, now a subsidiary of Xperi. It has litigated extensively at the US ITC against Qualcomm, Broadcom, Samsung, Toshiba, Motorola, STMicroelectronics and Freescale. Also taken on crates.io, npm and PyPI. **Same industry as this project — an unacceptable risk.** |
| **NEXILIS** | ⛔ rejected | Registered trademark of NEXILIS AG (US Reg. 5093458). Also taken on npm, with multiple active companies using the name. |
| **LIMEN** | ⛔ rejected | Multiple live USPTO applications in classes 009 and 042 plus a registered EU mark. Also taken on crates.io. |
| **PONTIS** | ⛔ rejected | `PONTIS` is a registered trademark of AASHTO for bridge-management software; crates.io `pontis` taken. |
| **CARDO** | ⛔ rejected | CARDO SYSTEMS LTD holds the mark; crates.io `cardo` taken. |
| **VADUM / BIVIUM / ARTUS / KOINE** | ⛔ rejected | Active companies or taken registries in each case. |

---

## 3. MEASURED NAMESPACE STATE

Measured 2026-10-18 with `tools/namespace_probe.py`. **A 404 means unclaimed.**

| Namespace | `compitum` | `compitum-dev` |
|---|---|---|
| GitHub | ⛔ **TAKEN** — abandoned 2014 personal account, last activity 2017, one unrelated repo (`JEM-3`) | ✅ **FREE** |
| npm | ✅ **OURS** — claimed, `0.0.2` is `latest` | ✅ FREE |
| PyPI | ✅ FREE | ✅ FREE |
| crates.io | ✅ FREE | ✅ FREE |
| Container (GHCR) | inherits the GitHub org — no separate signup | ✅ FREE |

### Domain state

| Domain | State |
|---|---|
| `compitum.io` | ⛔ **TAKEN** — an active AI-tools portfolio site (`ns73.domaincontrol.com`). Not ours, unrelated field. |
| `compitum.dev` | ✅ no DNS delegation — appears available |
| `compitum.org` | ✅ no DNS delegation — appears available |
| `compitum-dev.com` | ✅ appears available |
| `compitumdev.com` | ✅ appears available |

**Note on method:** an earlier probe reported Docker Hub as taken for every candidate.
That was a tool defect, not a finding: `/v2/repositories/<name>/` returns `200` with an
empty list for *any* name, including ones that certainly do not exist. The correct
endpoint is `/v2/users/<name>/`. The corrected probe is in `tools/namespace_probe.py`.
Recording this because a measurement error that survives into a decision is worse than
no measurement.

### Why Docker Hub is not a blocker

Container images will be published to **GHCR** (`ghcr.io/<github-org>/compitum`), which
requires no separate account and automatically inherits the GitHub organisation's
namespace. Docker Hub's `compitum` being taken is therefore irrelevant.

---

## 4. THE UNIFIED SCHEME

One product name, one identity, with the minimum possible divergence forced by reality.

| Purpose | Value | Note |
|---|---|---|
| **Product name** | `COMPITUM` | always uppercase in prose |
| **Canonical handle** | `compitum-dev` | used wherever a handle is needed |
| **GitHub organisation** | `compitum-dev` | the one handle we must diverge to; `compitum` is unavailable |
| **GitHub repository** | `compitum-dev/compitum` | project name stays `compitum` |
| **npm package** | `compitum` | ✅ already ours |
| **npm scope** | `@compitum-dev` | created automatically with the org |
| **PyPI package** | `compitum` | free |
| **crates.io package** | `compitum`, `compitum-*` | free |
| **Container** | `ghcr.io/compitum-dev/compitum` | no separate signup |
| **Email (transitional)** | `compitum.dev@gmail.com` | see §5 |
| **Email (permanent)** | `hello@compitum.dev` | once the domain is registered |
| **Domain (primary)** | `compitum.dev` | `.dev` is HSTS-preloaded: cannot be downgraded to plaintext |
| **Domain (secondary)** | `compitum-dev.com` | forward to the primary |

### Why `compitum-dev` and not `compitumdev`

Both are free. The hyphenated form is chosen for one reason: **`compitum-dev` reads as
`compitum` + `dev` rather than as one opaque word**, which keeps the product name
recognisable in a URL. `compitumdev` looks like a single invented string.

### The rule this establishes

> **The product is `COMPITUM`. The handle is `compitum-dev` only where `compitum` is
> already taken. Package names always use `compitum`, never the org suffix.**

So a user types `npm install compitum` and clones `github.com/compitum-dev/compitum`.
Both are predictable from the product name.

---

## 5. GMAIL: THE TECHNICAL FACT THAT DECIDES IT

### Gmail ignores dots

`compitum.dev@gmail.com` and `compitumdev@gmail.com` are **the same mailbox**. Dots in the
local part of a Gmail address are insignificant, and always have been. Anyone can also
create `c.ompitum.dev@gmail.com` etc. — they all route to the same account, and *there is
no way to prevent this*. Whoever owns the undotted form owns every dotted variant.

### What this means for the choice

Because dots are cosmetic, the address should be chosen for **how it reads**, not for its
uniqueness:

> ### Recommended: `compitum.dev@gmail.com`

Three reasons, in order of weight:

1. **It already signals the domain you intend to own.** When `compitum.dev` is registered
   and mail forwarding is set up, the transition from `compitum.dev@gmail.com` to
   `hello@compitum.dev` is invisible to everyone who ever corresponded with you.
2. **It normalises to `compitumdev@gmail.com`**, which closely matches the GitHub org
   handle `compitum-dev`. The three functions of the name line up.
3. **It is not tied to a personal identity.** `pajand@gmail.com` cannot be handed to a
   co-maintainer or a future legal entity. A project address can.

### Alternatives, ranked

| Address | Assessment |
|---|---|
| `compitum.dev@gmail.com` | ✅ **recommended** — signals the domain, matches the handle |
| `compitum.project@gmail.com` | ✅ good — unambiguous, but longer |
| `compitum.arm64@gmail.com` | ⚠️ too narrow; the project will outgrow "arm64" |
| `compitum.abi@gmail.com` | ⚠️ too jargon-heavy for a first contact address |
| anything containing `pajand` | ❌ ties the project to one person permanently |

### What to check before committing

Gmail availability cannot be probed programmatically. Check the exact address on the
signup form; if the undotted form is refused, a dotted variant may not help (Google
normalises for uniqueness too), so fall back to the second-ranked option.

---

## 6. EXECUTION ORDER

Irreversibility decreases downward; do them in this order.

| # | Action | Where | Automated? |
|---|---|---|---|
| 1 | Claim the npm placeholders | npm | ✅ already done — `compitum@0.0.2` |
| 2 | Create the Gmail address | gmail.com | ❌ manual (needs your phone) |
| 3 | Create the GitHub organisation `compitum-dev` | github.com | ❌ **manual — the API cannot create organisations** |
| 4 | Transfer the repo into the org | GitHub settings | ❌ manual |
| 5 | Register `compitum.dev` | any registrar | ❌ manual (needs payment) |
| 6 | Create the crates.io token, then publish | crates.io | ✅ automatable with your token |
| 7 | Publish `compitum` and `compitum-*` to crates.io | crates.io | ✅ automatable |
| 8 | Publish `compitum` to PyPI | pypi.org | ✅ automatable |
| 9 | Re-point npm metadata at the org URL | npm | ✅ automatable |
| 10 | File the USPTO intent-to-use for classes 009 + 042 | USPTO | ❌ later, month 1–3 |

### Why the organisation, not your user account

The repository currently lives at `compitum-dev/compitum`. That works, but it makes the project
identity depend on a personal account. An organisation:

- survives losing access to a personal account,
- can hold team members and package scopes,
- makes `ghcr.io/compitum-dev/...` possible,
- and is what an outside contributor expects to see.

**The API cannot create organisations** — this is a deliberate GitHub restriction, not a
permissions problem. It takes about two minutes in the web UI.

---

## 7. WHAT WOULD FORCE A RENAME

Stated in advance, so the decision is not revisited casually:

| Condition | Response |
|---|---|
| A trademark is granted to a third party in classes 009 or 042 | rename immediately |
| A funded company launches an ARM64 compatibility product named COMPITUM | negotiate or rename |
| USPTO refuses the application on a citing mark | rename before the mark is used commercially at scale |
| Nothing above occurs | **never rename.** Stability is worth more than a marginally better word. |

A rename after publication costs every downstream reference: registries, container tags,
CI files in other people's repositories, and citations in papers. It should happen at
most once, and it has already happened once.
