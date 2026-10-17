# NAME ACQUISITION AND DEFENCE PLAN

**Asset:** the project name **COMPITUM**
**Risk:** a name that is not claimed within days of first public exposure can be taken
by a squatter, a competitor, or a well-meaning third party — and once taken in a
registry or a trademark office it is expensive or impossible to reclaim.
**Status:** T-0 is imminent. Act on the ordering below.

---

## 0. WHY THIS DOCUMENT EXISTS

The original working name was rejected after due diligence because it collided with a
litigious semiconductor company. That check cost minutes and saved the project:
a trademark conflict discovered after a public launch costs legal fees, forced renames
of already-published packages, and the permanent loss of the primary domain.

**This document is the repeatable version of that check.**

The plan follows one principle:

> **Claim in order of *irreversibility*, cheapest and most reversible first.**
>
> A GitHub org can be renamed in five minutes. A crate name cannot be reclaimed if
> someone else publishes under it. A registered trademark is a months-long, irreversible
> commitment that must come last, after the name has earned it.

---

## 1. THE ORDERING — ACT IN EXACTLY THIS SEQUENCE

| # | Action | Cost | Reversible? | Deadline |
|---|---|---|---|---|
| 1 | Reserve crates.io names | free | no | **Day 1 — before any public commit** |
| 2 | Reserve npm + PyPI names | free | no | Day 1 |
| 3 | Register GitHub org + repo | free | yes (renamable) | Day 1 |
| 4 | Register the primary domain | ~10 USD/yr | yes (transferable) | Day 1–2 |
| 5 | Reserve the remaining TLDs and handles | ~50 USD | yes | Week 1 |
| 6 | Publish a v0.0.1 to every registry | free | no (but keeps the name) | Week 1 |
| 7 | Publish a public repo + LICENSE | free | yes | Week 1 |
| 8 | File trademark **intent-to-use** | ~250–400 USD | no | Month 1–3 |
| 9 | Hire an IP lawyer only if commercial traction appears | — | — | Month 6+ |

**Steps 1–4 are today's work.** Everything else can wait. Everything before step 6 is
*worse than useless on its own*: reserving a name without publishing an artifact leaves
it reclaimable under most registries' dormancy rules.

---

## 2. STEP 1 — REGISTRIES (IRREVERSIBLE, DO FIRST)

### Why this is first

A registry name, once published, is permanent and defensible. Until it is published it
is only a reservation, and reservations can be reaped. **Publishing a trivial `0.0.1`
is the actual act of claiming.**

### Commands

Authenticate once, then publish every name. Each crate needs a `Cargo.toml`, a
`src/lib.rs` with at least a doc comment, and a description — a registry entry cannot
be published without a description.

```bash
# One-time: create an API token at https://crates.io/settings/tokens
export CARGO_REGISTRY_TOKEN='<token>'

for name in compitum compitum-json compitum-i18n compitum-isa \
            compitum-pe compitum-router compitum-oracle compitum-cli; do
  echo "--- $name"
  cargo publish -p "$name" --allow-dirty
done
```

```bash
# npm: claim the name as a placeholder package so nobody else can
npm login
for name in compitum compitum-cli; do
  mkdir -p "/tmp/npm-$name" && cd "/tmp/npm-$name"
  cat > package.json <<EOF
{ "name": "$name", "version": "0.0.1", "description": "Reserved by the COMPITUM Project.",
  "license": "MIT", "repository": "github:compitum/compitum" }
EOF
  echo "// reserved placeholder" > index.js
  npm publish --access public
done
```

```bash
# PyPI: names are claimed on first upload and never expire
python3 -m pip install --user build twine
mkdir -p /tmp/pypi-compitum && cd /tmp/pypi-compitum
cat > pyproject.toml <<'EOF'
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "compitum"
version = "0.0.1"
description = "Reserved by the COMPITUM Project."
readme = "README.md"
license = { text = "MIT" }
EOF
echo "# compitum" > README.md
mkdir -p src/compitum && echo "" > src/compitum/__init__.py
python3 -m build && python3 -m twine upload dist/*
```

**Note on crates.io squatters.** crates.io enforces a "no squatting" policy and will
transfer a name to a party with a legitimate claim. This is a *remedy, not a
protection*: it takes weeks and requires evidence of use. Publish first.

---

## 3. STEP 2 — GITHUB (REVERSIBLE, SO SECOND)

GitHub organizations are free, and both usernames and repositories can be renamed
later without breaking clones (GitHub inserts the redirect). So this is cheap — but do
it early anyway, because the namespace also carries the credibility signal.

```bash
# Create the org at https://github.com/organizations/new  (name: compitum)
# Then reserve the *organisation handle* even if the product repo starts under a user.
```

Create these repositories so the namespaces cannot be taken by another party:

| Repository | Purpose |
|---|---|
| `compitum` | primary monorepo |
| `compitum-oracle-data` | the compatibility dataset (the moat) |
| `compitum-locales` | community translations |
| `compitum-ports` | per-platform integration notes |
| `.github` | org-wide policy, security, contribution templates |

**Immediately:** enable branch protection on `main`, require signed commits, enable
Dependabot, and add a `SECURITY.md`. A project that will hold a dataset worth scraping
needs its supply chain locked down from the first commit.

---

## 4. STEP 3 — DOMAIN

Register in this priority order. Only the first is required.

| Domain | Why | Priority |
|---|---|---|
| `compitum.dev` | canonical developer home; `.dev` is HSTS-preloaded so it cannot be downgraded | **required** |
| `compitum.io` | the address people guess first | high |
| `compitum.org` | non-profit and documentation mirror | medium |
| `compitum.sh`, `compitum.rs` | ecosystem-idiomatic short links | low |
| `getcompitum.com` | fallback if the dot-com route is needed later | low |

**Do not** attempt `compitum.com` unless it is cheap. Spending five figures on a domain
before the product has a user is a misuse of the budget; the `.dev` carries the same
authority for developer tooling.

**Configure immediately after registration:**
- DNSSEC, and an SPF/DKIM/DMARC record set (even if no mail is sent yet — an unauthenticated
  domain gets spoofed, and that erodes trust in the name)
- A `CAA` record so no other CA can issue for the domain
- Redirects from every secondary domain to the canonical one

---

## 5. STEP 4 — SOCIAL AND PACKAGE HANDLES

Claim before someone builds an audience on your name. Handle consistency matters more
than completeness.

| Platform | Handle | Priority |
|---|---|---|
| GitHub | `compitum` | required (done in step 2) |
| X / Twitter | `compitum` or `compitumdev` | required |
| Mastodon / Fediverse | `@compitum@fosstodon.org` | high |
| Reddit | `r/compitum` | medium |
| Discord | server vanity `compitum` | medium |
| LinkedIn | company page | medium |
| Hacker News, Lobsters | username `compitum` | low but free |
| Docker Hub | `compitum/compitum` | **high — needed for distribution** |
| GHCR | `ghcr.io/compitum/compitum` | high |

**The ones people forget and later regret:** Docker Hub, because container images are a
primary distribution channel for a compatibility layer; and the CI runner marketplace
namespaces (GitHub Actions Marketplace, GitLab CI Catalog), because those names appear
in other people's configuration files.

---

## 6. STEP 5 — TRADEMARK (IRREVERSIBLE, SO LAST)

### The strategy: intent-to-use, not use

Most jurisdictions allow filing before commercial use. In the United States this is a
**Section 1(b) intent-to-use** application: it fixes your priority date, can be
maintained for years by filing extensions, and converts to a registration once you ship.

**Why it belongs here in the ordering and not earlier:** a trademark filing is
expensive, slow, and jurisdiction-limited, and it commits you to a name. It should
follow proof that the name is worth defending. Filing on day one of a project that may
pivot is how founders end up with a portfolio of dead marks.

### Where to file, in order

| Jurisdiction | Class | When | Approx. cost |
|---|---|---|---|
| United States (USPTO) | 009 (software) + 042 (SaaS) | Month 1–3 | 250–400 USD per class |
| European Union (EUIPO) | 009 + 042 | Month 6 | ~850 EUR, covers all 27 states |
| United Kingdom (IPO) | 009 + 042 | Month 12 | ~170 GBP |

**Classes 009 and 042 are the two that matter.** Class 009 covers downloadable software;
class 042 covers software-as-a-service and design services. Filing only 009 leaves the
SaaS product — which is this project's primary revenue line — unprotected.

### The screening you must do before filing

Do not rely on the availability check that was already performed for creative naming.
A trademark clearance search is a different and stricter exercise:

1. **USPTO TESS/Trademark Search** — search the exact mark and the two closest phonetic
   and visual variants, in classes 009 and 042, live and dead.
2. **EUIPO eSearch plus** and **WIPO Global Brand Database** — for international marks
   that have effect in your markets.
3. **Common-law search** — web, app stores, GitHub, Crunchbase. In the United States,
   unregistered use still creates rights in the geographic area of use.
4. **Domain and handle sweep** — a name already used by an active product in an adjacent
   class is a practical conflict even when it is not a legal one.

Record the results in `docs/ip/CLEARANCE-<date>.md`. An auditable clearance file is what
lets a lawyer give you a fast answer instead of starting from zero.

### What *not* to do

- Do not file a mark you have not searched. A failed application does not just waste the
  fee; it creates a public record of the attempt.
- Do not use the `™` symbol to imply a registration you do not have. `™` asserts
  common-law rights and is fine; `®` is a legal claim and is only lawful after
  registration in that jurisdiction.
- Do not skip class 042 because it sounds like "services".

---

## 7. ONGOING DEFENCE

Claiming is a one-time act; keeping the name is continuous.

| Threat | Control | Cadence |
|---|---|---|
| Registry squatter in an unclaimed ecosystem (Homebrew, AUR, Winget, Chocolatey, Flatpak) | Claim the package name in every user-facing package manager | Week 1, then quarterly |
| Typosquatting on registries | Register the closest misspellings defensively where free | Quarterly |
| Domain expiry hijack | Auto-renew on, registrar lock on, 2FA on | Yearly |
| Phishing / impersonation | Publish a `security.txt` naming your only official channels | Week 1 |
| Credential loss on the namespace account | Hardware key 2FA on crates.io, GitHub, registrar, npm, PyPI | **today** |
| Hostile fork claiming to be the project | Clear LICENSE, CONTRIBUTING, and a `TRADEMARK.md` stating the usage policy | Week 1 |
| Dataset scraping and re-hosting | Document the license on the Oracle dataset explicitly | With the dataset |

**The one that gets projects killed: losing the namespace account.** If the only holder
of the crates.io or domain credential is locked out, the name becomes unrecoverable even
though nobody "stole" it. Put a hardware security key on every namespace account, and
store recovery codes in the encrypted vault — not in the repository.

---

## 8. WHAT TO DO RIGHT NOW

Ordered, with the irreversibility of each step in mind.

- [ ] **Today — 30 minutes.** Create a crates.io token, a GitHub org, and a PyPI account.
      Turn on 2FA for all three.
- [ ] **Today — 1 hour.** Publish `compitum-json` and `compitum` as `0.0.1` placeholders.
      A published crate is a claimed crate.
- [ ] **Today — 15 minutes.** Register `compitum.dev`. Enable auto-renew and registrar lock.
- [ ] **Today — 15 minutes.** Claim `compitum` on Docker Hub, X, and Mastodon.
- [ ] **This week.** Create the organisation repositories, add `LICENSE`,
      `CONTRIBUTING.md`, `SECURITY.md`, `TRADEMARK.md`.
- [ ] **This week.** Publish placeholders to npm and PyPI.
- [ ] **This month.** Run the full clearance search and record it in
      `docs/ip/CLEARANCE-<date>.md`.
- [ ] **Months 1–3.** File the USPTO intent-to-use application for classes 009 and 042.

---

## 9. DECISION RECORD

| Date | Decision | Evidence |
|---|---|---|
| 2026-10-18 | Rejected `TESSERA` | Collides with Tessera Technologies / Tessera Inc., a semiconductor IP company (subsidiary of Xperi, formerly NASDAQ:TSRA) with extensive litigation history. Also taken on crates.io, npm and PyPI. |
| 2026-10-18 | Rejected `NEXILIS` | Registered trademark of NEXILIS AG (US Reg. 5093458); taken on npm; multiple active companies. |
| 2026-10-18 | Rejected `LIMEN` | Multiple live USPTO applications in classes 009 and 042 plus a registered EU mark; taken on crates.io. |
| 2026-10-18 | Rejected `PONTIS` | `PONTIS` is a registered trademark of AASHTO for bridge-management software, and crates.io `pontis` is taken. |
| 2026-10-18 | Rejected `CARDO` | CARDO SYSTEMS LTD holds the mark; crates.io `cardo` is taken. |
| 2026-10-18 | **Selected `COMPITUM`** | Latin *compitum*, "a crossroads" — the precise function of an ABI router. Verified absent on crates.io, npm, PyPI and GitHub orgs; no trademark found in classes 009/042. |
