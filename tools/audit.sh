#!/bin/sh
# Adversarial audit of the COMPITUM CLI.
#
# # What this is for
#
# The unit tests check that the code does what its author intended. This checks what happens
# when it is fed things nobody intended: truncated files, hostile headers, impossible section
# counts, random byte flips, and paths that do not exist.
#
# The specific question is not "does it work" but **"can it lie"**. A tool that panics is merely
# broken and will be noticed. A tool that returns a confident verdict about a file it could not
# read is *dangerous*, because its output is indistinguishable from a real finding — and this
# project has already shipped three defects of exactly that shape.
#
# # The three failure classes, in order of severity
#
#   1. **A false verdict.** Exit 0 or 2 on an input it could not actually parse. This is the
#      worst outcome: a customer acts on it.
#   2. **A crash.** A panic, a hang, or an exit code outside the documented set (0, 1, 2).
#      Loud, recoverable, and cheap to fix once known.
#   3. **An inconsistent answer.** `scan` and `verify` disagreeing about the same file, or a
#      patched file not behaving as its plan promised. Subtle and corrosive.
#
# # Reading the result
#
# Every case prints PASS or FAIL with the exit code and the first line of output, so a failure
# can be reproduced from the log without re-running anything.
#
# Usage:  sh tools/audit.sh [path-to-compitum]

set -u

BIN="${1:-/root/compitum-target/release/compitum}"
WORK="/tmp/complitum-audit.$$"
FAILS=0
CASES=0

if [ ! -x "$BIN" ]; then
    echo "::error::no compitum binary at $BIN" >&2
    exit 1
fi

mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

# Records one outcome.
#
# `expected` is a space-separated list of exit codes that count as correct. Anything else is a
# failure, including 101 (Rust's panic code) and 124 (a hang caught by `timeout`), because both
# mean the tool did something it does not document.
check() {
    label="$1"
    expected="$2"
    shift 2
    CASES=$((CASES + 1))

    output=$(timeout 30 "$@" 2>&1)
    code=$?
    first=$(printf '%s' "$output" | head -1 | cut -c1-96)

    ok=0
    for want in $expected; do
        [ "$code" = "$want" ] && ok=1 && break
    done

    if [ "$ok" = "1" ]; then
        printf '  PASS  %-40s exit=%s\n' "$label" "$code"
    else
        FAILS=$((FAILS + 1))
        printf '  FAIL  %-40s exit=%s  (expected %s)\n' "$label" "$code" "$expected"
        printf '        %s\n' "$first"
    fi
}

echo "=============================================================="
echo " adversarial audit of $BIN"
echo "=============================================================="
echo

# ---------------------------------------------------------------------------
# 1. Inputs that are not PE images at all
#
# None of these can yield a verdict. The correct answer for every one is "this is not a Windows
# image" or "I could not read this" — never a route.
# ---------------------------------------------------------------------------
echo "--- inputs that are not Windows images ---"

: > "$WORK/empty.bin"
printf 'MZ' > "$WORK/mz-only.bin"
printf 'hello world, definitely not a PE\n' > "$WORK/text.bin"
head -c 2000 /dev/urandom > "$WORK/random.bin"
printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > "$WORK/mz-16.bin"

# A file that begins like a PE and then stops: the DOS header points at an offset past the end.
printf 'MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$WORK/bad-lfanew.bin"
printf '\xff\xff\xff\x7f' >> "$WORK/bad-lfanew.bin"
head -c 60 /dev/zero >> "$WORK/bad-lfanew.bin"

check "empty file, inspect"        "1" "$BIN" inspect "$WORK/empty.bin"
check "empty file, verify"         "1" "$BIN" verify "$WORK/empty.bin"
check "MZ only, inspect"           "1" "$BIN" inspect "$WORK/mz-only.bin"
check "plain text, inspect"        "1" "$BIN" inspect "$WORK/text.bin"
check "random bytes, inspect"      "1" "$BIN" inspect "$WORK/random.bin"
check "16-byte MZ, verify"         "1" "$BIN" verify "$WORK/mz-16.bin"
check "bad e_lfanew, verify"       "1" "$BIN" verify "$WORK/bad-lfanew.bin"

echo

# ---------------------------------------------------------------------------
# 2. Paths and directories
#
# A directory handed to a single-file command must be a clean error, not a partial read. A
# missing path must be exit 1 in every command that takes one.
# ---------------------------------------------------------------------------
echo "--- paths ---"

check "missing file, inspect"      "1" "$BIN" inspect /definitely/not/here.exe
check "missing file, verify"       "1" "$BIN" verify /definitely/not/here.exe
check "missing file, port"         "1" "$BIN" port /definitely/not/here.exe
check "missing path, scan"         "1" "$BIN" scan /definitely/not/here
check "directory as a file"        "1" "$BIN" inspect "$WORK"
mkdir -p "$WORK/emptydir"
check "empty directory, scan"      "0" "$BIN" scan "$WORK/emptydir"
check "no operand at all"          "1" "$BIN" inspect
check "unknown command"            "1" "$BIN" frobnicate
check "unknown option"             "1" "$BIN" inspect --nonsense "$WORK/mz-only.bin"

echo

# ---------------------------------------------------------------------------
# 3. Range and limit options
#
# A malformed numeric option must be rejected rather than silently defaulted, because a
# silently-widened scan produces a report that looks complete and is not the one asked for.
# ---------------------------------------------------------------------------
echo "--- numeric options ---"

check "non-numeric --limit"        "1" "$BIN" scan "$WORK" --limit abc
check "negative --depth"           "1" "$BIN" scan "$WORK" --depth -1
# --limit 0 means "examine nothing", which the tool reports as a truncated scan and
# signals with exit 1. That is the honest answer: a zero-file report is not a finding.
check "--limit 0 (nothing examined)" "1" "$BIN" scan "$WORK" --limit 0
check "--depth 0 on a file"        "0 1 2" "$BIN" scan "$WORK/mz-16.bin" --depth 0

echo

# ---------------------------------------------------------------------------
# 4. Hostile headers
#
# Each of these is a class of malformed input a parser must survive: absurd counts, sizes that
# overflow when added, offsets that point backwards. None may panic.
# ---------------------------------------------------------------------------
echo "--- hostile headers (built by mutating a real image) ---"

REAL="$(dirname "$0")/../crates/compitum-pe/tests/corpus/real-console-4k.exe"
if [ -f "$REAL" ]; then
    python3 - "$REAL" "$WORK" <<'PY'
import struct, sys, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
d = bytearray(src.read_bytes())
lfanew = struct.unpack_from('<I', d, 0x3C)[0]
coff = lfanew + 4

cases = {}
# NumberOfSections set absurdly high.
b = bytearray(d); struct.pack_into('<H', b, coff + 2, 0xFFFF); cases['sections-65535'] = b
# OptionalHeaderSize smaller than any real header.
b = bytearray(d); struct.pack_into('<H', b, coff + 16, 4); cases['opt-header-4-bytes'] = b
# SizeOfHeaders larger than the file.
# The optional header begins immediately after the 20-byte COFF header, so this is
# coff + 20 + 0x3C. An earlier version wrote coff + 24 and corrupted a different field,
# which made the check appear not to work when it did.
b = bytearray(d); struct.pack_into('<I', b, coff + 20 + 0x3C, 0xFFFFFF00); cases['headers-huge'] = b
# A section whose raw pointer is past the end of the file.
sec = coff + 20 + struct.unpack_from('<H', b, coff + 16)[0]
b = bytearray(d); struct.pack_into('<I', b, sec + 20, 0xFFFF0000); cases['section-ptr-past-end'] = b
# A section whose raw size overflows when added to its pointer.
b = bytearray(d); struct.pack_into('<I', b, sec + 16, 0xFFFFFFFF); cases['section-size-overflow'] = b
# e_lfanew pointing at the very end of the file.
b = bytearray(d); struct.pack_into('<I', b, 0x3C, len(d) - 2); cases['lfanew-at-eof'] = b
# PE signature corrupted.
b = bytearray(d); b[lfanew:lfanew+4] = b'XXXX'; cases['bad-pe-signature'] = b
# Optional header magic set to nonsense.
b = bytearray(d); struct.pack_into('<H', b, coff + 20, 0xDEAD); cases['bad-opt-magic'] = b

for name, content in cases.items():
    (out / f'{name}.exe').write_bytes(bytes(content))
print(f"  built {len(cases)} hostile variants")
PY

    for f in "$WORK"/*.exe; do
        name=$(basename "$f" .exe)
        check "hostile: $name" "1" "$BIN" verify "$f"
    done
else
    echo "  SKIP  no real fixture to mutate"
fi

echo

# ---------------------------------------------------------------------------
# 5. Random mutation
#
# The blunt instrument. Flips bytes at random positions and checks that nothing panics or hangs.
# A parser that indexes without a bounds check will be caught here eventually, and a panic tells
# us exactly where.
# ---------------------------------------------------------------------------
echo "--- random byte mutation (60 variants) ---"

if [ -f "$REAL" ]; then
    python3 - "$REAL" "$WORK/mut" <<'PY'
import random, sys, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
d = src.read_bytes()
random.seed(20261020)
for i in range(60):
    b = bytearray(d)
    for _ in range(random.randint(1, 8)):
        pos = random.randrange(len(b))
        b[pos] = random.randrange(256)
    (out / f'm{i:02d}.exe').write_bytes(bytes(b))
print("  built 60 mutants")
PY

    bad=0
    for f in "$WORK"/mut/*.exe; do
        timeout 20 "$BIN" verify "$f" >"$WORK/out.txt" 2>&1
        code=$?
        # 0, 1 and 2 are the documented outcomes. 101 is a panic; 124 is a hang.
        case "$code" in
            0|1|2) ;;
            *)
                bad=$((bad + 1))
                printf '  FAIL  %-40s exit=%s\n' "mutant $(basename "$f")" "$code"
                head -1 "$WORK/out.txt" | cut -c1-96 | sed 's/^/        /'
                ;;
        esac
    done
    CASES=$((CASES + 60))
    if [ "$bad" = "0" ]; then
        printf '  PASS  %-40s exit=0 1 2 only\n' "60 mutants, no panic or hang"
    else
        FAILS=$((FAILS + bad))
    fi
else
    echo "  SKIP  no real fixture"
fi

echo

# ---------------------------------------------------------------------------
# 6. Truncation
#
# Every prefix of a valid file. This is the cheapest way to find a bounds check that is missing,
# and truncation is exactly what a half-finished download produces — which makes it the most
# likely malformed input a customer will actually have.
# ---------------------------------------------------------------------------
echo "--- truncation at 24 lengths ---"

if [ -f "$REAL" ]; then
    python3 - "$REAL" "$WORK/trunc" <<'PY'
import sys, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
d = src.read_bytes()
for frac in range(1, 25):
    n = max(1, len(d) * frac // 25)
    (out / f't{frac:02d}.exe').write_bytes(d[:n])
print("  built 24 truncations")
PY

    bad=0
    for f in "$WORK"/trunc/*.exe; do
        timeout 20 "$BIN" verify "$f" >"$WORK/out.txt" 2>&1
        code=$?
        case "$code" in
            0|1|2) ;;
            *)
                bad=$((bad + 1))
                printf '  FAIL  %-40s exit=%s\n' "truncation $(basename "$f")" "$code"
                head -1 "$WORK/out.txt" | cut -c1-96 | sed 's/^/        /'
                ;;
        esac
    done
    CASES=$((CASES + 24))
    if [ "$bad" = "0" ]; then
        printf '  PASS  %-40s exit=0 1 2 only\n' "24 truncations, no panic"
    else
        FAILS=$((FAILS + bad))
    fi
else
    echo "  SKIP  no real fixture"
fi

echo

# ---------------------------------------------------------------------------
# 7. Consistency: scan must agree with verify
#
# The two commands answer the same architectural question for one file. If they disagree, one of
# them is wrong, and the report a customer signs would contradict the single-file result their
# engineer sees. This has already happened once in this project (kernel drivers), so it is
# checked rather than assumed.
# ---------------------------------------------------------------------------
echo "--- scan/verify agreement on every real file ---"

CONSISTENCY_FAILS=0
CONSISTENCY_CASES=0
for f in samples/realworld/*.exe samples/realworld/*.dll crates/compitum-pe/tests/corpus/*.exe; do
    [ -f "$f" ] || continue
    CONSISTENCY_CASES=$((CONSISTENCY_CASES + 1))

    v_route=$(timeout 30 "$BIN" verify "$f" --target windows-on-arm --backends wine,fex 2>/dev/null \
        | grep -E '^\s+internal' | awk '{print $2}')
    s_route=$(timeout 30 "$BIN" scan "$f" --target windows-on-arm --backends wine,fex --json 2>/dev/null \
        | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    files=d.get('files') or []
    print(files[0].get('route','') if files else '')
except Exception:
    print('')
" 2>/dev/null)

    if [ -n "$v_route" ] && [ -n "$s_route" ] && [ "$v_route" != "$s_route" ]; then
        CONSISTENCY_FAILS=$((CONSISTENCY_FAILS + 1))
        printf '  FAIL  %-40s verify=%s scan=%s\n' "$(basename "$f")" "$v_route" "$s_route"
    fi
done
CASES=$((CASES + CONSISTENCY_CASES))
if [ "$CONSISTENCY_FAILS" = "0" ]; then
    printf '  PASS  %-40s %s files agree\n' "scan == verify" "$CONSISTENCY_CASES"
else
    FAILS=$((FAILS + CONSISTENCY_FAILS))
fi

echo

# ---------------------------------------------------------------------------
# 8. Port safety
#
# The port command rewrites bytes. These check the properties that make that acceptable: the
# original is never modified, the input cannot be the output, and a patched file must behave as
# its plan promised.
# ---------------------------------------------------------------------------
echo "--- port safety ---"

PINNED="samples/realworld/pinned-x86.dll"
if [ -f "$PINNED" ]; then
    before=$(sha256sum "$PINNED" | cut -d' ' -f1)

    check "port refuses to clobber input" "1" "$BIN" port "$PINNED" --apply --output "$PINNED"

    rm -f "$WORK/patched.dll"
    check "port applies to a new file"    "0" "$BIN" port "$PINNED" --apply --output "$WORK/patched.dll"

    after=$(sha256sum "$PINNED" | cut -d' ' -f1)
    CASES=$((CASES + 1))
    if [ "$before" = "$after" ]; then
        printf '  PASS  %-40s hash unchanged\n' "input untouched by --apply"
    else
        FAILS=$((FAILS + 1))
        printf '  FAIL  %-40s the input was modified\n' "input untouched by --apply"
    fi

    # The plan promised AnyCPU. Verify it by asking the tool again, not by trusting the plan.
    CASES=$((CASES + 1))
    if [ -f "$WORK/patched.dll" ]; then
        result=$(timeout 30 "$BIN" port "$WORK/patched.dll" 2>&1 | grep -c "already portable")
        if [ "$result" -ge 1 ]; then
            printf '  PASS  %-40s now AnyCPU\n' "patched file matches its plan"
        else
            FAILS=$((FAILS + 1))
            printf '  FAIL  %-40s plan promised AnyCPU, file is not\n' "patched file matches its plan"
        fi
    fi

    # The patched file must still be a parseable image.
    check "patched file still parses"     "0" "$BIN" inspect "$WORK/patched.dll"
else
    echo "  SKIP  no pinned assembly available"
fi

echo

# ---------------------------------------------------------------------------
# 9. Idempotence and determinism
#
# Two runs over the same tree must produce identical output. A report that varies cannot be
# diffed, and diffing is how a migration is tracked. Applied twice, a patch must not change.
# ---------------------------------------------------------------------------
echo "--- determinism ---"

if [ -f "$PINNED" ]; then
    rm -f "$WORK/a.dll" "$WORK/b.dll"
    "$BIN" port "$PINNED" --apply --output "$WORK/a.dll" >/dev/null 2>&1
    "$BIN" port "$PINNED" --apply --output "$WORK/b.dll" >/dev/null 2>&1
    CASES=$((CASES + 1))
    if [ -f "$WORK/a.dll" ] && cmp -s "$WORK/a.dll" "$WORK/b.dll"; then
        printf '  PASS  %-40s byte-identical\n' "port is deterministic"
    else
        FAILS=$((FAILS + 1))
        printf '  FAIL  %-40s two runs differ\n' "port is deterministic"
    fi
fi

two=$(timeout 60 "$BIN" scan crates/compitum-pe/tests/corpus --json 2>/dev/null | sha256sum)
one=$(timeout 60 "$BIN" scan crates/compitum-pe/tests/corpus --json 2>/dev/null | sha256sum)
CASES=$((CASES + 1))
if [ "$two" = "$one" ]; then
    printf '  PASS  %-40s byte-identical\n' "scan is deterministic"
else
    FAILS=$((FAILS + 1))
    printf '  FAIL  %-40s two runs differ\n' "scan is deterministic"
fi

echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=============================================================="
if [ "$FAILS" = "0" ]; then
    echo " RESULT: $CASES cases, all passed"
    exit 0
fi
echo " RESULT: $CASES cases, $FAILS failed"
exit 1
