# Phase 1 feasibility: measured, not assumed

**Date:** 2026-10-18
**Status:** measured on the development device
**Verdict:** the execution bridge is **already partly working**, and the gap is a known,
dated one rather than an open research problem.

---

## The question this answers

Phase 1 of the roadmap is the execution bridge: proving that a real ARM64 Windows executable
runs on ARM64 Linux. The plan assumed a from-source build of `proton-wine` (a gigabyte of C
plus twenty dependencies), which the roadmap itself flagged as a memory and libc risk.

Before spending hours on that, the cheapest possible test was run instead:

> **Is Wine already present, and can it execute a real ARM64 Windows PE binary?**

It can.

---

## What was measured

### 1. Wine is already installed, and it is an aarch64 build

```console
$ wine --version
wine-6.0.3 (Ubuntu 6.0.3~repack-1)
$ ls /usr/lib/aarch64-linux-gnu/wine/ | head
acledit.dll.so  aclui.dll.so  activeds.dll.so  ...
```

Ubuntu 22.04 ships Wine 6.0.3 for arm64. No build was required.

### 2. It executes a real compiler-produced ARM64 Windows PE binary

The corpus file `real-console-4k.exe` was built by `clang` and `lld-link` for the
`aarch64-pc-windows-msvc` target. Its `entry()` is an infinite loop and it makes no NT calls,
so a correct result is "runs forever", not "exits cleanly". That makes it an ideal probe: a
loader that rejects it fails fast, and a loader that runs it cannot return.

```console
$ timeout 15 wine real-console-4k.exe
exit 124        # 124 = the timeout expired, i.e. the program was still running
```

### 3. The controls separate correctly

A single result proves little without controls. Three inputs with known expected outcomes:

| Input | Expected | Observed | Interpretation |
|---|---|---|---|
| A file that is not a PE | rejected fast | exit 47 | Wine refuses non-PE input |
| ARMNT (`0x01C4`, 32-bit ARM) | rejected | exit 32 | Wine 6.0.3 has no 32-bit ARM support |
| `real-console-4k.exe` (ARM64) | runs to timeout | **exit 124** | **Wine executed it** |

The middle row matters: Wine is not accepting everything. It rejects an unsupported machine
type with a distinct code, so the ARM64 result is a genuine acceptance rather than a fallback.

### 4. Proof that the code was *executed*, not merely loaded

Exit 124 could, in principle, mean a hung loader. So CPU time was measured directly from the
kernel, which distinguishes execution from blocking:

```text
idle baseline (our process absent)   :  56 jiffies
our process after 8 s wall time      : 657 jiffies  = 6.6 CPU-seconds
```

An infinite loop that consumes 6.6 of 8 available CPU-seconds is being **executed**. A process
that had blocked on a lock or a missing resource would have accumulated almost none.

**This is the Phase 1 milestone, met on the development device.**

---

## What does *not* work, and why that is expected

| Input | Machine | CHPE | Result |
|---|---|---|---|
| `real-console-4k.exe` | `0xAA64` | — | **runs** (exit 124) |
| `real-gui-4k.exe` | `0xAA64` | — | **runs** (exit 124) |
| `chpe-arm64ec.exe` | `0x8664` | version 1 | exit 123, refused |
| `chpe-arm64x.exe` | `0xAA64` | version 2 | exit 5, page fault at the image base |
| ARMNT | `0x01C4` | — | exit 32, refused |

The ARM64EC refusal is **correct and dated**, not a defect:

> Wine 8.21 (October 2023) — "Beginnings of support for ARM64EC target"

Wine 6.0.3 predates ARM64EC support by more than two years. The roadmap's plan to use a
`proton-wine` build was right for a reason it had not yet articulated: **the installed Wine is
too old for the hybrid case, and only the native case is solved.**

The ARM64X page fault is an artefact of the fixture, not a Wine limitation. That file was
constructed for header testing and its `AddressOfEntryPoint` is zero, so Wine jumped to the
image base and faulted. The fact that it *attempted* execution is itself mild evidence that the
image was accepted.

---

## What this changes about the plan

**Before:** build `proton-wine` from source, risking hours of work on an unproven premise.

**Now:** the bridge is proven to work for native ARM64 with software already installed. The
remaining work is narrower and better understood:

| Task | Was | Is |
|---|---|---|
| Native ARM64 execution | assumed to need a build | **works today** |
| ARM64EC hybrid execution | assumed to need a build | needs Wine ≥ 8.21, or a `proton-wine` build |
| NT syscall translation | untested | partially proven: Wine 6.0.3 loaded and ran a real PE |
| Build cost | unknown | **avoidable for the native case** |

The dependency for the hybrid case is now a **version floor**, which is a far better problem to
have than an unknown.

---

## The narrower question that remains

Wine 6.0.3 is the only aarch64 Wine available from Ubuntu 22.04's archive:
`wine64-development` also resolves to `6.0+repack-1ubuntu1`.

So supporting ARM64EC needs one of:

1. **A newer Wine from elsewhere** — WineHQ publishes source; arm64 packages are the open
   question, and building 8.21+ for arm64 on this device is the build the roadmap feared.
2. **`proton-wine`**, which the roadmap already identified and which carries an `arm64ec`
   target, built from source.
3. **`FEX` on its own**, which cannot serve a *Windows* binary without Wine's NT layer, so
   this is not an independent option.

Option 2 is the roadmap's original plan and remains the right one — but it is now a
**hybrid-only** task rather than the whole bridge.

---

## How to reproduce

```console
# Ubuntu environment (glibc, which is what Wine targets)
$ cp crates/compitum-pe/tests/corpus/real-console-4k.exe /tmp/
$ timeout 15 wine /tmp/real-console-4k.exe; echo "exit: $?"
exit: 124      # still running, therefore executed

# Control: a non-PE file must be refused
$ printf 'not a PE' > /tmp/notpe.exe
$ wine /tmp/notpe.exe; echo "exit: $?"
exit: 47
```

---

## What this does *not* claim

- It does **not** claim arbitrary ARM64 Windows applications run. The probe makes no NT calls,
  so NT syscall translation is exercised only as far as process startup.
- It does **not** claim ARM64EC works. It does not, and the reason is a dated version floor.
- It does **not** replace the roadmap's execution-bridge milestones. It establishes that the
  first of them is already met, which narrows the rest.
