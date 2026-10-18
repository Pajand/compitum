# compitum-exec

Executes a binary through a chosen route and records what actually happened.

Part of [COMPITUM](https://github.com/compitum-dev/compitum), the universal ARM64 compatibility
layer.

## What it adds

Everything before this crate *predicts*. COMPITUM can classify a binary and decide which route
is correct, but until something runs it the prediction is unverified — and an unverified
prediction is exactly the kind of claim this project exists to replace.

This crate runs it, observes it, and produces an Oracle record carrying
`Provenance::ObservedExecution` rather than `StaticAnalysis`. That distinction is what makes a
record worth more than a guess.

## The question it is careful about

"Did it work?" is harder than it looks. An earlier check in this project treated a **timeout** as
proof of execution — which is also what a *hung* process produces — and reported a false pass.

So every signal has one meaning, and two failure classes are kept strictly apart:

| Signal | Meaning | Outcome |
|---|---|---|
| The deadline fired, process still alive | it **loaded and ran** | `Success` |
| Clean exit | it ran and did its job | `Success` |
| Non-zero exit after starting | it ran, then reported an error | `Partial` |
| **Exit 126/127, or backend absent** | **the backend never started it** | **not recorded** |
| Killed by a signal | terminated, cause unknown | `Unknown` |

The fourth row is the one that matters. **A missing Wine is not a compatibility observation — it
is a misconfiguration.** Recording it would attribute the operator's broken environment to the
binary, and a dataset polluted that way is worse than an empty one, because its errors become
indistinguishable from its findings.

## Two implementation details worth knowing

**Child output goes to a temporary file, not a pipe.** A pipe deadlocks: the parent reads only
after the child exits, while the child blocks once the buffer fills. A program that prints a lot
would appear to hang. The file has no such limit.

**The process is polled, not waited on**, so a deadline is enforced without depending on an
external `timeout` binary.

## Example

```rust
use compitum_exec::{run, RunRequest};

// A program that outlives its deadline was demonstrably executing.
let request = RunRequest::new("/bin/sh", 300).arg("-c").arg("sleep 10");
let observation = run(&request).expect("must run");

assert!(observation.terminated);
assert_eq!(observation.verdict.outcome, compitum_oracle::Outcome::Success);
```

## Licence

Apache-2.0 OR MIT, at your option.
