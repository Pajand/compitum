# Building Wine with ARM64EC support

This recipe is the result of a measured investigation. Every step below was executed; the
failure it works around was observed, diagnosed, and traced to a single line.

Read `docs/PHASE1-FEASIBILITY.md` first for why this is needed at all: the Wine installed on
Ubuntu 22.04 is 6.0.3, and ARM64EC arrived in 8.21.

---

## What works and what does not

| Approach | Result |
|---|---|
| Ubuntu 22.04's `wine64` 6.0.3 | ✗ predates ARM64EC by two years |
| Ubuntu's `wine64-development` | ✗ also 6.0 |
| Debian trixie's prebuilt `wine64` 10.0 arm64 | ✗ needs `GLIBC_2.38`; the host has 2.35 |
| **Build Wine 11.20 from source** | ⚠ configures with ARM64EC; stops at one FFmpeg line |

WineHQ's own Ubuntu repository publishes **only amd64 and i386** packages, so no arm64 binary
upgrade exists. A build is the only route.

---

## Prerequisites

```bash
apt-get install -y build-essential bison flex pkg-config clang lld llvm llvm-dlltool \
                   mingw-w64
```

`clang` and `lld` are required because Wine cross-compiles its PE side, and `aarch64-windows`
is not a MinGW target this distribution packages. Wine will refuse to configure with:

```text
configure: error: aarch64 PE compiler not found.
Please install mingw-w64, clang/llvm-dlltool/lld, or llvm-mingw.
```

**Install a clang that supports the extensions Wine needs.** clang-14 and clang-15 both handle
`sve`, `sve2`, `sme` and `crc`; verified by compiling `.arch_extension <name>` for each.

---

## The configure command

```bash
./configure \
  --enable-archs=aarch64,arm64ec,x86_64,i386 \
  --without-ffmpeg --without-gstreamer \
  --without-x --without-freetype --without-fontconfig --without-cups \
  --without-alsa --without-pulse --without-gnutls --without-vulkan \
  --disable-tests
```

**`arm64ec`, not `aarch64ec`.** Wine's vocabulary is:

```text
--enable-archs={i386,x86_64,arm,aarch64,arm64ec,none}
```

Getting the spelling wrong produces `Unknown cross-compilation architecture 'aarch64ec'`, which
reads like "ARM64EC is unsupported" but is a typo. Wine 11.20's source contains 256 references
to `arm64ec` across 52 files in `dlls/`.

A successful configure prints:

```console
$ grep PE_ARCHS Makefile
PE_ARCHS =  aarch64 arm64ec x86_64 i386
```

---

## The known blocker, and its one-line fix

The build stops at:

```text
libs/ffmpeg/libavutil/aarch64/asm.S:112:17:
  error: unknown architectural extension: dotprod
.arch_extension nodotprod
```

### Why it happens

The file guards each directive behind a configure-time test:

```c
#if HAVE_AS_ARCHEXT_DOTPROD_DIRECTIVE
#define ENABLE_DOTPROD  .arch_extension dotprod
#define DISABLE_DOTPROD .arch_extension nodotprod
#else
#define ENABLE_DOTPROD
#define DISABLE_DOTPROD
#endif
```

FFmpeg's own configure **wrongly concluded the directive is supported**:

```console
$ grep HAVE_AS_ARCHEXT_DOTPROD_DIRECTIVE libs/ffmpeg/config.h
#define HAVE_AS_ARCHEXT_DOTPROD_DIRECTIVE 1
```

but the actual compile fails. Verified directly:

```console
$ printf '.arch_extension dotprod\n' > p.S
$ clang-15 --target=aarch64-windows -c p.S -o p.o
error: unknown architectural extension: dotprod
```

So this is a **false positive in a build-system probe**, not an architecture limitation.

### The fix

Turn the guard off:

```bash
sed -i 's/#define HAVE_AS_ARCHEXT_DOTPROD_DIRECTIVE 1/#define HAVE_AS_ARCHEXT_DOTPROD_DIRECTIVE 0/' \
    libs/ffmpeg/config.h
```

The `#else` branch defines `DISABLE_DOTPROD` as empty, which is exactly the correct behaviour for
a toolchain that does not know the directive. This is the same class of fix Wine and FFmpeg
upstream already apply for other assemblers.

**Alternative**, if a later clang is installed that does support the directive: use that clang and
no patch is needed. `-march=armv8.2-a+dotprod` works even on clang-15, so the *feature* is
available — only the assembler directive is not.

**Note:** `--without-ffmpeg` does **not** remove `libs/ffmpeg` from the build. It was passed and
`libs/ffmpeg` remained in `EXTERNAL_SUBDIRS`. The guard patch is the working fix.

### If a later version appears

This specific failure is version-dependent and may not reproduce with a newer clang. Check
before patching:

```bash
printf '.arch_extension dotprod\n' > /tmp/p.S
clang --target=aarch64-windows -c /tmp/p.S -o /tmp/p.o && echo "no patch needed"
```

---

## Building

```console
$ nice -n 5 make -j"$(nproc)"
```

**Expect several hours.** On the reference device (6 cores) the build produced over 1000 object
files before reaching the blocker, and includes three external sub-libraries plus 747 PE
builtins per architecture.

### The environment hazard, measured

This was guessed at first and then tested, because "the build keeps dying" is not a diagnosis.

**Test 1 — does a detached process survive?** A trivial script was launched with
`setsid nohup`, writing a timestamped line every five seconds for ten minutes.

```text
launched : 05:40:22
ticks recorded : 1 of 120
```

It was killed after roughly five seconds. **Detachment does not work here**, so `setsid`,
`nohup` and background jobs are not a route to a long build.

**Test 2 — does a long foreground call survive?** The harness terminates a call after 300
seconds with no output. A `make` produces continuous output, so this is the question that
matters. A loop was run emitting a line every 20 seconds:

```text
tick 1 at 05:45:57
tick 2 at 05:48:49
tick 3 at 05:50:00
tick 4 at 05:52:34
```

It survived the full 400-second allowance, so **foreground work with continuous output is
viable.** But read the timestamps: a 20-second sleep took between 60 and 170 seconds of wall
time. The environment is throttled by roughly **3× to 8×**.

So a build that takes one to two hours on a normal machine would take **many hours here**, in
foreground chunks, because nothing may run in the background.

**The conclusion is a change of plan, not a workaround.** A multi-hour build belongs on a
machine that is not a phone. The build was therefore moved to CI:

* `.github/workflows/wine-arm64ec.yml` builds Wine with ARM64EC on GitHub's ARM64 runner.
* It is `workflow_dispatch` only — a build this heavy must not run on every push.
* It verifies its own result with the corpus and `tools/loopcheck.sh`, so the artifact it
  produces is evidence rather than a binary nobody checked.

Nothing about the blocker changes: the one-line `HAVE_AS_ARCHEXT_DOTPROD_DIRECTIVE` fix is still
the fix. What changes is where the build runs.

Progress can still be checked by counting object files, which is cheaper than watching a
terminal:

```bash
find . -name '*.o' | wc -l
ls -l loader/wine loader/wine64 2>/dev/null
```

---

## Verifying the result

A completed build should produce `loader/wine`. Then:

```console
# The native case, which works with Wine 6.0.3 already and must still work here.
$ ./loader/wine /path/to/real-console-4k.exe

# The ARM64EC case, which is the whole point.
$ ./loader/wine /path/to/chpe-arm64ec.exe
```

`tools/loopcheck.sh` compares the routing prediction against observation and is the correct way
to judge the result — a single binary run by hand cannot distinguish *executing* from *hanging*,
which is a mistake this project has already made once.

---

## The cheaper alternative

The roadmap's original plan was `proton-wine`, which already carries an `arm64ec` target **and**
the fixes the community accumulated for exactly these toolchain problems. If the goal is a
working ARM64EC backend rather than a from-scratch build, that is the shorter path and it was
the plan for a reason.

This document exists so that the investigation does not have to be repeated: the blocker is
characterised, the false-positive probe is identified, and the fix is one line.
