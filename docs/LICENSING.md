# Licensing and commercial policy

**Status:** in force
**Date:** 2026-10-18
**Applies to:** every artefact this project produces — code, binary, dataset, schema and brand

> This document is a policy statement, not legal advice. It is written to be specific enough
> that a lawyer can review it in minutes rather than starting from nothing, and specific enough
> that a company evaluating COMPITUM for production knows exactly what it is agreeing to.

---

## 1. The decision, stated plainly

| Layer | Licence | Commercial use |
|---|---|---|
| **Source code** (all Rust crates and helper scripts) | `Apache-2.0 OR MIT` | ✅ **Permitted, free, no permission needed** |
| **CLI and library binaries** | same as the source they are built from | ✅ **Permitted, free** |
| **Oracle JSON schema and record format** | `Apache-2.0` | ✅ **Permitted, free — deliberately** |
| **Community-contributed observations** | `ODbL-1.0` (copyleft data) | ✅ Permitted, **but derived databases must stay open** |
| **Verified / curated compatibility data** | **Proprietary** | 💰 **Commercial licence required** |
| **Hosted Oracle API** | **Proprietary service** | 💰 **Commercial subscription** |
| **Migration-validation engagements** | Contract | 💰 **Commercial** |
| **Support, SLA and legal indemnity** | Contract | 💰 **Commercial** |
| **The name COMPITUM** | Trademark policy | ⛔ Not granted with the code |

---

## 2. Why the code is open, and why that is not a mistake

### It is already irreversible, and it was the right choice anyway

Version `0.1.0` is published on crates.io under `Apache-2.0 OR MIT`. **That version can never be
relicensed** for anyone who obtained it. What remains controllable is every future version and
every non-code artefact.

### Because the code is not the moat

This is the whole argument, and it is worth being blunt about it:

| The code | The data |
|---|---|
| ~16,000 lines of Rust | Thousands of "this binary works on that machine" observations |
| Any competent engineer reproduces it in a week | Cannot be bought at any price |
| Value of a copy: near zero | Value of a copy: the entire business |

A permissive licence is therefore not generosity. It is the cheapest customer-acquisition
mechanism available, because it removes the two things that block adoption inside a company:

1. **Legal review.** `Apache-2.0` and `MIT` are on every corporate approved-licence list.
   `GPL`, `AGPL` and most source-available licences are not.
2. **Procurement.** No purchase order is needed. An engineer can try it this afternoon.

A restrictive licence would produce: no corporate adoption → no observations → no dataset →
no moat → no revenue. **The permissive licence is what makes the asset exist.**

---

## 3. The trap this policy explicitly avoids

### Open core with a permissive licence does not work

The common plan is: release a free core, sell "Pro" features in the same repository.

**With `Apache-2.0`, a competitor may take the entire codebase, delete the paid feature-gate,
and sell the result. Nothing in the licence prevents this.** This is not hypothetical: it is why
Redis, Elastic and HashiCorp all changed licence, and why each change produced a hostile
community reaction that permanently damaged trust.

**Therefore this project does not sell permission to use code it published as free.** It never
will. The "never paid" list in §4 is a commitment, not a marketing line, and it exists because a
project that later reneges on it loses the community that produced its asset.

---

## 4. What will **never** be paid

Stated as a commitment so that no future decision can quietly reverse it:

- ❌ The classifier, the router, or the CLI. Not feature-gated, not time-limited, not "Pro".
- ❌ The ability to inspect a binary and get a verdict, locally, offline, without limit.
- ❌ The local ledger. Recording your own observations on your own machine is free forever.
- ❌ Reading or writing the Oracle record format.
- ❌ Self-hosting. Anyone may run their own Oracle instance from the open source.

**Why this list matters commercially, not just ethically:** a company will contribute
observations to a dataset only if it believes the dataset cannot later be enclosed. Publishing
that guarantee up front is what makes the contributions arrive.

---

## 5. The data licences, and why they differ

This is the section that decides whether the business works. Two datasets, two licences,
**kept physically separate**.

### 5.1 `oracle-community` — `ODbL-1.0`

Observations contributed by users and by the community.

**Why a copyleft data licence and not a permissive one:** `ODbL` is a share-alike licence
designed specifically for databases. It permits commercial use, but requires that a
**derivative database** be released under the same terms.

The legal effect is exactly what the business needs:

> A competitor may use the community dataset commercially.
> A competitor **may not take it, improve it, and enclose the improvement.**

With `CC0` or a permissive data licence, a competitor could re-host the dataset behind a
paywall. With `ODbL`, the improvement must stay open — so **no one can enclose the moat**, and
the only way to compete on data is to contribute to it.

`ODbL` also carries an EU **sui generis database right** grant, which matters because that right
is the actual legal hook for database protection in Europe.

**Produced works are not affected.** A compatibility report, a migration assessment, a
screenshot, a chart — these are *produced works*, not derivative databases, and `ODbL` does not
force them open. That distinction is what makes §5.2 possible.

### 5.2 `oracle-verified` — proprietary

Data this project produces itself: measurements taken on the test farm, on hardware we control,
under a repeatable method.

**Why this can be proprietary:** it is generated independently and is not derived from the
community dataset. A licence on contributed data cannot reach data that was never derived from
it.

**Why it is kept in a separate database rather than merged:** merging the two would make the
combined database a derivative of the `ODbL` one, and the whole of it would then be subject to
share-alike — including the proprietary half.

### ⚠️ The correction: a joined query is not a safe middle ground

An earlier revision of this document said the stores could be "queryable together" and that
"queries may join them at the API layer". **That was wrong, and the correction matters more than
anything else in this file.**

`ODbL` §4.4(c) states:

> *"A Derivative Database is Publicly Used and so must comply with Section 4.4 if a Produced Work
> created from the Derivative Database is Publicly Used."*

and §4.6 adds:

> *…you must offer recipients the entire Derivative Database machine-readable.*

Read together, the consequence is precise and unforgiving:

| Operation | Legal effect |
|---|---|
| Query each store separately, return separate results | ✅ No derivative database created |
| Materialise a joined table and serve answers from it | ⛔ **The join itself is a Derivative Database** |
| Serve a chart produced from that join | ⛔ §4.4(c) pulls the join in |
| …without offering the whole join as machine-readable data | ⛔ §4.6 breach |

So "join at the API layer" is **not** a legal middle ground. It is the exact operation the
share-alike clause exists to catch, and it would place the proprietary dataset under an
obligation to be given away.

> ### The rule, stated so it cannot be misread again
>
> **The two stores are never combined — not on disk, and not in a query.**
>
> A response may draw from one store or the other. It may not draw from a table that contains
> both. Where a caller needs both kinds of information, the API returns two labelled sections
> and the **composition happens on the caller's side**, in the caller's own system, under the
> caller's own obligations.

**Engineering consequence, and it is enforced in code:** `compitum-oracle`'s `StoreBoundary`
holds the two directories explicitly and refuses any arrangement in which one store contains the
other, because nesting is how the two would become a single database by accident. See
`crates/compitum-oracle/src/store.rs`.

**A second consequence for the hosted API:** because caching a join is itself a Derivative
Database, the API must not cache mixed results either. Two caches, two datasets, no mixed
materialisation.

### 5.3 Schema — `Apache-2.0`

The record format and JSON schema are licensed permissively, deliberately. Others must be able to
read and write the format without asking, because a format that requires a licence to implement
does not spread. **A schema that spreads is what makes the dataset valuable.**

---

## 6. Where the revenue actually comes from

Recorded honestly, because a plan that assumes licensing revenue from a free tool is not a plan.

### 6.1 The streams

| Stream | What the buyer is actually paying for | Timeline | Realistic scale |
|---|---|---|---|
| **Migration-validation engagement** | Work: "which of our 2,000 internal binaries break on ARM64, and how" | month 6+ | $10k–50k per project |
| **Oracle API, commercial tier** | Convenience and freshness of data at scale | month 12+ | subscription |
| **CI runner licence** | Running verification across a fleet, unattended | month 6–12 | $500–2,000/yr |
| **Support, SLA, indemnity** | **A promise.** Companies buy liability transfer, not code | month 18+ | negotiated |
| **Acquisition** | The dataset, the schema and the team | any time | strategic |
| **Credibility** | Not revenue — but it is why the other rows are reachable | immediate | — |

### 6.2 The honest ranking

1. **Consulting is the realistic first revenue.** A company migrating a fleet to ARM64 has a
   concrete, funded problem today. COMPITUM is the instrument that answers it. This is the only
   stream that can be invoiced before the dataset is large.
2. **The API becomes real once the dataset is real**, which needs roughly twelve to eighteen
   months of contributions. Selling it earlier sells an empty database.
3. **Licence sales of the tool itself are the weakest stream.** A permissively licensed CLI is
   routinely run without anyone paying, and that is the intended behaviour. Do not build the
   plan on it.
4. **The credible acquisition case is the dataset.** A silicon vendor shipping ARM64 parts has a
   direct interest in knowing which software works on them.

### 6.3 The timeline, and the mistake to avoid

```
month 0–6     code is free, dataset is small, revenue is ~zero
month 6–12    consulting begins on real migrations
month 12–18   API becomes sellable because the dataset is no longer empty
month 18+     support and SLA contracts on top
```

> **The mistake is expecting revenue from the free layer.** Revenue comes from *patience applied
> to a free layer*: adoption first, data second, money third. Any attempt to reverse that order
> — by gating features, by delaying the open release, by charging for the CLI — collapses the
> adoption that the whole plan rests on.

---

## 7. Contributions

- **Code:** contributed under a **DCO** (Developer Certificate of Origin), signed off with
  `git commit -s`. This is the lightest mechanism that establishes provenance, and it is what
  Linux and Git use in place of an assignment agreement.
- **Data:** a contribution of observations is accepted under `ODbL-1.0`, and the contributor
  confirms they have the right to license it.
- **No copyright assignment is required.** Contributors keep their copyright; the DCO records
  only that the contribution may be distributed under the project's licence.

---

## 8. Telemetry and privacy

Any automatic contribution of observations is **explicitly opt-in**, never on by default,
and documented in plain language before it is enabled. Recording behaviour:

- **Never collects the binary itself**, only its SHA-256, its declared properties and the verdict.
- **Never collects file paths, user names or machine identifiers.**
- **Can be disabled** with `--no-record`, which is a visible flag rather than an implied
  consequence of another option, and the local ledger keeps working regardless.

The reasoning is not only ethical. A dataset of questionable provenance is a **liability in an
acquisition** and a legal exposure under GDPR — the EU *sui generis* database right and the
personal-data regime both apply. **Consent obtained properly is an asset; consent skipped is a
discount on the sale price.**

---

## 9. What a commercial licence would cover

For clarity about what §6.1 rows actually sell, since "commercial licence" is otherwise vague:

| Covered | Not covered |
|---|---|
| Access to the `oracle-verified` dataset | The right to redistribute the open source code (already granted) |
| Hosted API with an availability commitment | The COMPITUM name or logo |
| A support SLA with defined response times | Any warranty beyond what the contract states |
| Legal indemnity for the licensed data | Permission to sublicense the verified dataset |
| Priority on schema changes | — |

---

## 10. Summary

1. **Code is free, permanently.** Irreversible for `0.1.0`; intended for every version after it.
2. **Community data is `ODbL`** — usable commercially, impossible to enclose.
3. **Verified data is proprietary**, and is kept in a separate store so that the share-alike
   obligation cannot reach it. **The two stores are never combined — not on disk, and not in a
   query.** A join is itself a Derivative Database under §4.4(c).
4. **The schema is `Apache-2.0`**, because a format that spreads is what makes the data valuable.
5. **Revenue is consulting, data and promises — in that order of practicality.** Not licences.
6. **The "never paid" list is a commitment.** It is the reason contributions arrive.

**The strategy in one sentence:**

> Give away the thing that is cheap to copy and expensive to discover, and sell the thing that
> is expensive to copy and impossible to discover twice.
