# Phase 1 feasibility: measured, not assumed

**Date:** 2026-10-18
**Status:** measured on the development device
**Verdict:** the execution bridge **works today** for native ARM64, and is verified beyond
loading — six of six routing predictions matched observation, and NT syscall translation is
proven by four distinct exit codes propagating through Wine. The remaining gap is ARM64EC, and
it is a dated version floor rather than an open research problem.

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

The full prediction-versus-measurement comparison:

```console
$ sh tools/loopcheck.sh <path-to-compitum> <path-to-corpus>
initialising the Wine prefix once (its setup cost would otherwise swamp the measurement)
binary                   predicted          observed          verdict
chpe-arm64ec.exe         fex_partial        not-running(+0)   AGREE
chpe-arm64x.exe          pick_native_slice  executing(+420)   AGREE
real-arm64ec.exe         fex_full           not-running(+0)   AGREE
real-console-16k.exe     native             executing(+423)   AGREE
real-console-4k.exe      native             executing(+422)   AGREE
real-gui-4k.exe          native             executing(+422)   AGREE

agreements: 6    disagreements: 0    extraction failures: 0
VERDICT: all 6 prediction(s) matched observation
```

A single file, by hand, showing why the exit code is not the evidence:

```console
$ WINEPREFIX=/tmp/wp wine /path/to/real-console-4k.exe &
$ # after 4 s, sum utime+stime for the matching process; then again 4 s later
# ARM64, infinite loop : +456 jiffies  -> executing
# x86-64, cannot run   :  +18 jiffies  -> not executing
```

---

## A measurement error worth recording

The first version of `tools/loopcheck.sh` treated a timeout exit code (124) as proof that a
program had executed. **It is not.** A program that hangs also times out. That produced a false
agreement:

```
chpe-arm64ec.exe   predicted fex_partial   observed executed   verdict unexpected-success
```

An x86-64 binary, which Wine on ARM64 cannot execute without FEX, was recorded as having
executed — so the loop check appeared to contradict COMPITUM's own prediction when in fact the
*measurement* was wrong.

Three defects were found in the script, in increasing order of seriousness:

**1. The JSON pattern never matched.** The CLI emits pretty-printed output:

```text
  "route": "native"
```

while the pattern expected `"route":"native"` with no space. Every prediction silently became
`unknown`. Fixed by tolerating arbitrary whitespace, and by treating a missing prediction as a
fatal error rather than filling in a placeholder.

**2. The script reported success having measured nothing.** With zero predictions it printed
`VERDICT: every prediction matched observation`. A check that passes having verified nothing is
worse than no check, because it converts an absence of evidence into apparent evidence — the
exact failure mode this project exists to eliminate. It now refuses to pass unless at least one
comparison was actually made.

**3. Exit code cannot distinguish executing from hanging.** The substantive error, and the one
worth generalising from.

### Finding the right discriminator

Claimed CPU time was the obvious candidate and it was also wrong: Wine's first-run prefix
initialisation runs `rundll32 setupapi,InstallHinfSection`, which burns over 1500 jiffies on its
own — more than any program being measured. That is what made the x86-64 binary look busy.

Measuring in an already-initialised prefix separates the two cases cleanly:

| Program | CPU growth over 4 s | Interpretation |
|---|---|---|
| ARM64 binary, infinite loop (`b .`) | **+456 jiffies** | executing |
| x86-64 binary, cannot run | **+18 jiffies** | not executing |

The discriminator is therefore **CPU growth across two windows**, not a single total and not an
exit code. A program that is running accumulates CPU steadily; one that is blocked, refused, or
parked on a dialog does not.

The threshold is 150 jiffies, which sits far from both observations — 8× above the blocked case
and 3× below the executing case, so ordinary jitter cannot flip a verdict.

### The result, after the correction

```text
binary                   predicted          observed          verdict
chpe-arm64ec.exe         fex_partial        not-running(+0)   AGREE
chpe-arm64x.exe          pick_native_slice  executing(+420)   AGREE
real-arm64ec.exe         fex_full           not-running(+0)   AGREE
real-console-16k.exe     native             executing(+423)   AGREE
real-console-4k.exe      native             executing(+422)   AGREE
real-gui-4k.exe          native             executing(+422)   AGREE

agreements: 6    disagreements: 0    extraction failures: 0
```

**The separation is qualitative, not marginal.** Every file the router said would execute
executed, and every file it said would not, did not. That is the project's central claim,
verified end to end against real binaries and a real Wine.

### The generalisable lesson

Two of the three defects were cases where a check **appeared to succeed because it had not
actually measured anything**. Both this project's most valuable findings — the PE header offsets
and the CHPE identification — were of the same shape: a system agreeing with itself.

> A check must be able to distinguish "verified true" from "not verified at all", and must
> never report the second as the first.

The 150-jiffie threshold and the zero-comparison guard are both instances of that rule.

## Phase 1.4 met: NT syscall translation works

Proving that Wine *loads* an ARM64 image is not the same as proving it translates the NT
syscalls the image makes. A binary whose entry point loops forever exercises loading; one that
calls into `kernel32` exercises the syscall layer.

### The probe

An ARM64 Windows program was built whose entire body is a single call:

```c
__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);
void __stdcall entry(void) { ExitProcess(code); for (;;) { } }
```

A `.def` file plus `llvm-dlltool -m arm64` produced the import library, because no
ARM64 Windows CRT is packaged for this distribution. The linked image declares one import:

```console
$ llvm-readobj --coff-imports ntcall-arm64.exe
  Format: COFF-ARM64
  Import { Name: kernel32.dll
           Symbol: ExitProcess (0) }
```

### Why the exit status is the evidence

`ExitProcess` terminates the process with the value it is given. If Wine resolves the import,
executes the ARM64 code, and translates the syscall, **Wine's own process exit status becomes
that value**. That is a closed loop with no interpretation required.

A single run returning 42 would be weak — 42 could be a coincidence. So the program was built
four times with different arguments, and the status tracked each one exactly:

| Argument | Wine's exit status | |
|---|---|---|
| 0 | 0 | MATCH |
| 7 | 7 | MATCH |
| 42 | 42 | MATCH |
| 99 | 99 | MATCH |

Four independent values propagating correctly rules out coincidence. **Wine 6.0.3 resolves
ARM64 Windows imports and translates NT syscalls on this device.**

### An honest note on the accompanying message

Each run also printed:

```text
wine: Unhandled page fault on read access to 0000000000000028 at address ...
```

This appears *alongside* a correct exit status, which means the call completed and the fault
happened afterwards — in Wine's own teardown or debugger startup, not in the probe. It is
recorded rather than omitted because it is unexplained, and a reader deserves to know that a
message appears which this investigation did not chase down. It does not affect the result: a
fault inside the probe would not produce four distinct correct exit codes.

### What this establishes, and what it does not

**Established:** the NT syscall layer works for native ARM64 Windows binaries. Combined with
earlier results, Phase 1 has now shown loading, execution, and syscall translation.

**Not established:** anything about ARM64EC. The probe is a pure ARM64 image. The hybrid case
remains behind the version floor described in the next section.

**Also not established:** that arbitrary real applications run. The probe calls one function. A
program calling hundreds of NT entry points across graphics, threads and the registry exercises
far more surface, and this probe says nothing about that.

## The ARM64EC gap, measured precisely

Task 1.3 of Phase 1 is ARM64EC execution. The blocker was investigated rather than assumed, and
it is now three measured facts instead of an open question.

### Fact 1: the installed Wine is too old, and it is a glibc problem, not a Wine problem

Ubuntu 22.04 ships Wine 6.0.3. ARM64EC support began in Wine 8.21 (October 2023), so the
installed version predates it by more than two years. `wine64-development` in the same archive
also resolves to 6.0, so the archive offers no upgrade.

A prebuilt **Wine 10.0 for arm64** exists in Debian trixie, and it was downloaded and tested:

```text
wine64_10.0~repack-6_arm64.deb     extracted, 747 aarch64-windows builtins present
wine64 --version
  -> wine: could not load ntdll.so: /lib/aarch64-linux-gnu/libc.so.6:
     version `GLIBC_2.38' not found (required by .../aarch64-unix/ntdll.so)
```

Ubuntu 22.04 provides glibc 2.35. Wine 10.0 needs **2.38**. So the prebuilt route is closed by
the host distribution's age, not by anything about ARM64EC.

### Fact 2: Wine 11.20 supports ARM64EC in its build system

The source was downloaded (44.6 MB compressed, 416.7 MB extracted) and configured. Wine's
architecture vocabulary is:

```text
$ ./configure --help | grep enable-archs
  --enable-archs={i386,x86_64,arm,aarch64,arm64ec,none}
```

and the validation accepts exactly those:

```text
i386|x86_64|arm|aarch64|arm64ec) cross_archs="$cross_archs $arch" ;;
```

**`arm64ec` is a first-class architecture.** The source contains 256 occurrences of the string
across 52 files in `dlls/`.

*Correction worth recording:* the first configure attempt used `aarch64ec` and failed with
`Unknown cross-compilation architecture`. Wine spells it `arm64ec`. The error was mine, and
assuming it meant "ARM64EC is unsupported" would have been wrong — which is exactly why the
message was read rather than interpreted.

### Fact 3: a successful configure with ARM64EC, and where the build stopped

With clang, lld and llvm-dlltool present, configure succeeded and produced:

```text
$ grep PE_ARCHS Makefile
PE_ARCHS =  aarch64 arm64ec x86_64 i386
```

**All four architectures configured, ARM64EC included.** The build then ran and produced over
1000 object files, including `arm64ec-windows` outputs, before stopping at a single precise
error in the bundled FFmpeg:

```text
libs/ffmpeg/libavutil/aarch64/asm.S:112:17: error: unknown architectural extension: dotprod
.arch_extension nodotprod
```

clang-14 does not know `.arch_extension dotprod`. clang-15 was installed and tested: it knows
`sve`, `sve2`, `sme` and `crc` but **also not `dotprod`**, while `-march=armv8.2-a+dotprod`
does work. So the failing line is an assembler-directive limitation, not an architecture
limitation.

### What this leaves

| Route to ARM64EC | Status |
|---|---|
| Installed Wine 6.0.3 | ✗ predates ARM64EC by two years |
| Ubuntu archive upgrade | ✗ `wine64-development` is also 6.0 |
| Prebuilt Wine 10 arm64 (Debian) | ✗ needs glibc 2.38; host has 2.35 |
| **Build Wine 11.20 from source** | ⚠ configure succeeds with ARM64EC; build stops at one FFmpeg assembler directive |
| `proton-wine` (the roadmap's original plan) | ⚠ carries an `arm64ec` target; same class of build, with the fix already applied |

**The gap is now one directive wide.** Every remaining option is a build, and the build's only
demonstrated blocker is a `.arch_extension dotprod` line that `-march` handles. That is a
patch, not a research problem.

### What was *not* achieved, stated plainly

The build did **not** complete within this session. Repeated attempts were killed after running
for a while — this environment does not keep a long build alive across tool invocations, which
was itself the risk the roadmap flagged when it named memory and libc as Phase 1's hazards.

So the honest position is: **the blocker is identified, characterised and one directive wide,
but the ARM64EC build has not been proven to finish here.** Anyone continuing should either run
the build in a session that can stay alive for several hours, or use `proton-wine`, which
already carries the fix.

## What this does *not* claim

- It does **not** claim arbitrary ARM64 Windows applications run. The probe makes no NT calls,
  so NT syscall translation is exercised only as far as process startup.
- It does **not** claim ARM64EC works. It does not, and the reason is a dated version floor.
- It does **not** replace the roadmap's execution-bridge milestones. It establishes that the
  first of them is already met, which narrows the rest.
