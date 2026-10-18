# compitum

The command-line interface for [COMPITUM](https://github.com/compitum-dev/compitum), the universal
ARM64 compatibility layer.

## Install

```console
$ cargo install compitum-cli
```

Requires Rust 1.78 or later. No network access is needed to build.

## The question it answers

Every other tool in this space tells you *what* a binary is. This one tells you whether it
**will run on this machine**, and if not, exactly what is missing.

```console
$ compitum verify ./app.exe
COMPITUM — ./app.exe
Verdict
  Route        HYBRID
  internal       fex_partial
  Confidence     100%
  Emulation      fex
  expected       70-90% of native
Explanation
  Runs hybrid: the ARM64 functions execute natively and the x86-64 functions embedded in the
  same image are translated on demand.
Reason codes
  [!] architecture_hybrid: the AArch64 functions run natively; the embedded x86-64 functions
      require a translator
```

## The three ARM64 flavours, and why they differ

| Flavour | `Machine` | Contains | Route | Throughput |
|---|---|---|---|---|
| ARM64 | `0xAA64` | pure AArch64 | `native` | **100%** |
| ARM64X | `0xA64E` | both slices | `pick_native_slice` | **100%** |
| ARM64EC | `0xA641` | AArch64 **and x86-64** | `fex_partial` | 70-90% |
| x86-64 | `0x8664` | x86-64 only | `box64_full` | 20-50% |

An ARM64EC image genuinely contains x86-64 machine code, so it cannot run natively. But it is
not an x86-64 binary either: most of its code is already ARM64. A tool that treats "hybrid" as
"emulate everything" translates code that was already native, and loses most of the available
performance.

## Commands

| Command | Purpose |
|---|---|
| `compitum host` | Report this machine's ARM64 capabilities, and which are absent |
| `compitum inspect <binary>` | Classify a binary without consulting the host |
| `compitum verify <binary>` | Decide whether it can run here, and why |
| `compitum oracle <sub>` | Read and write the compatibility ledger |
| `compitum locales <sub>` | List, check and export translation catalogs |

## Exit codes

A tool used in CI must communicate its finding through its status, not only its text.

| Code | Meaning |
|---|---|
| `0` | Succeeded, and the verdict was favourable or not required |
| `1` | The command could not be carried out — bad input, unreadable file, bad option |
| `2` | `verify` ran successfully and the verdict was **not** favourable |

Distinguishing `1` from `2` matters: *"it will not run here"* is a result, while *"I could not
tell you"* is a failure, and a pipeline needs to treat them differently.

```console
$ compitum verify ./app.exe || echo "not runnable: $?"
```

## Examples

```console
$ compitum host
  Architecture   aarch64
  CPU cores      8
  Memory page size 4096 bytes
  hwcap          0x00000000ffbfffff
  hwcap2         0x0000000000022181
  Missing: sve sve2 sme mte bf16
```

Machine-readable output for a pipeline:

```console
$ compitum verify ./app.exe --json | jq -r .route
native
```

Recording a real observation, so the dataset grows from ordinary use:

```console
$ compitum oracle record ./app.exe --record-outcome success --note 'ran fine'
appended 9601c7e0 (success)
```

## Localization

English is compiled in, so the tool works with no external files. Adding a language means
dropping a JSON file beside the executable:

```console
$ compitum locales export fa > locales/fa.json   # a complete skeleton
$ compitum locales check fa                      # report remaining gaps
```

Machine output is **never** translated. JSON keys and route names are protocol values that
appear in stored records and in other people's configuration, so they stay English and stable.

## Honest limits

* **Translation backends are not auto-detected.** Discovering whether FEX is installed varies by
  distribution, and a false positive would make the tool promise a route it cannot take. Pass
  `--backends wine,fex` or `--assume-backends`.
* **SVE2 is not distinguished from SVE** by the instruction scanner. A binary needing SVE2 may
  therefore be reported as needing only SVE on a host that has SVE but not SVE2. The limitation
  is stated in `--verbose` output rather than hidden.
* **This tool does not execute anything.** It classifies and decides; running the binary is the
  job of an actual compatibility layer such as Wine plus FEX.

## Licence

Apache-2.0 OR MIT, at your option.
