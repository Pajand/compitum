#!/bin/sh
# Is exit code 124 sound evidence that a binary executed?
#
# # Why this question has to be answered by measurement
#
# Both `crates/compitum-exec` and `tools/probe-arm64ec.sh` treat a timeout as proof of
# execution: the corpus fixtures loop forever, so a fixture that loads runs until the
# deadline fires, while one that is refused exits immediately. That reasoning is only sound
# if nothing *else* can also make Wine sit there until the deadline.
#
# An exploratory run suggested something else can. A 16-byte file containing only the `MZ`
# signature -- which Wine cannot possibly execute -- returned 124 twice, exactly like the
# real fixture. If that is reproducible, "timed out" does not mean "executed", and every
# conclusion resting on it needs a second signal.
#
# So this script tests it directly, and it separates the two explanations:
#
#   * a wineserver COLD-START hang, which a warm-up removes, or
#   * a property of the files themselves, which no warm-up removes.
#
# The distinction matters because the fix is completely different in each case.
#
# # Method
#
# Two phases, identical work each:
#
#   PHASE A  kill the wineserver before every run  -> a cold start every time
#   PHASE B  keep the wineserver alive throughout  -> warm, after an explicit warm-up
#
# In both phases the negative controls (junk files Wine must refuse) are interleaved with
# the positive control (the real ARM64 fixture, which loops forever). Interleaving is
# deliberate: a bias that affects one file type but not the clock would otherwise look like
# a property of that file type.
#
# # Reading the result
#
# 124 must appear for `real` and never for `junk`/`plain`. Any 124 from a negative control
# means the exit code alone cannot decide, and the crate's rule is unsound as written.
#
# Usage:  sh tools/measure-timeout-signal.sh [corpus-dir]

set -u

CORPUS="${1:-crates/compitum-pe/tests/corpus}"
REAL="$CORPUS/real-console-4k.exe"
RUN_SECONDS=5
ROUNDS=8

if [ ! -f "$REAL" ]; then
    echo "::error::missing fixture: $REAL" >&2
    exit 1
fi

# Locate a Wine entry point the way the probe does: by whether it can run anything at all,
# not by whether a name resolves on PATH. Ubuntu installs the real loader at
# /usr/lib/wine/wine64 and puts only a wrapper on PATH.
WINE=""
for candidate in /usr/bin/wine64 /usr/lib/wine/wine64 /usr/bin/wine; do
    [ -x "$candidate" ] || continue
    WINE="$candidate"
    break
done
if [ -z "$WINE" ]; then
    echo "::error::no Wine entry point found; this measurement needs Wine installed" >&2
    exit 1
fi

export WINEPREFIX="${WINEPREFIX:-/tmp/wp-timeout-signal}"
export WINEDLLOVERRIDES="mscoree,mshtml="
rm -rf "$WINEPREFIX"
mkdir -p "$WINEPREFIX"

# The negative controls. Neither is a valid PE image, so neither can execute.
printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > /tmp/neg-junk.exe
printf 'hello, definitely not a PE file\n' > /tmp/neg-plain.txt

stop_wineserver() {
    timeout 15 "$WINE" wineserver -k </dev/null >/dev/null 2>&1 || true
    sleep 1
}

# Runs one file and reports exit code, elapsed milliseconds and captured bytes.
measure() {
    file="$1"
    started=$(date +%s%N)
    set +e
    timeout "$RUN_SECONDS" "$WINE" "$file" </dev/null >/tmp/measure.log 2>&1
    code=$?
    set -e
    ended=$(date +%s%N)
    elapsed_ms=$(( (ended - started) / 1000000 ))
    bytes=$(wc -c </tmp/measure.log | tr -d ' ')
    printf '  %-9s exit=%-4s %6s ms  %5s bytes\n' "$(basename "$file")" "$code" "$elapsed_ms" "$bytes"
}

trial() {
    round="$1"
    echo "  --- round $round"
    measure /tmp/neg-junk.exe
    measure /tmp/neg-plain.txt
    measure "$REAL"
}

echo "Wine entry point: $WINE"
echo "Wine version:     $(timeout 20 "$WINE" --version 2>&1 | head -1)"
echo "Fixture:          $REAL (entry point is an infinite loop)"
echo "Deadline:         ${RUN_SECONDS}s"
echo

# ---------------------------------------------------------------------------
# Warm-up. Deliberately before phase B, and reported, because whether a cold start is the
# cause is the entire question.
# ---------------------------------------------------------------------------
echo "WARMING UP (wineboot, then a throwaway run)"
timeout 60 "$WINE" wineboot -i </dev/null >/dev/null 2>&1 || true
timeout "$RUN_SECONDS" "$WINE" "$REAL" </dev/null >/dev/null 2>&1 || true
echo "warm-up done"
echo

echo "################################################################"
echo "### PHASE A: wineserver killed before every measurement       ###"
echo "###          (every run is a cold start)                      ###"
echo "################################################################"
phase_a_124=0
phase_a_neg_124=0
round=1
while [ "$round" -le "$ROUNDS" ]; do
    stop_wineserver
    output=$(trial "$round")
    echo "$output"
    # Count the 124s separately for the controls and the subject: that separation is the
    # whole point, and counting them together would hide the answer.
    echo "$output" | grep -q "neg-junk.*exit=124" && phase_a_neg_124=$((phase_a_neg_124 + 1))
    echo "$output" | grep -q "neg-plain.*exit=124" && phase_a_neg_124=$((phase_a_neg_124 + 1))
    echo "$output" | grep -q "real-console-4k.*exit=124" && phase_a_124=$((phase_a_124 + 1))
    round=$((round + 1))
done

echo
echo "################################################################"
echo "### PHASE B: one wineserver, kept warm throughout             ###"
echo "################################################################"
# Re-establish a clean daemon, then warm it fully before measuring.
stop_wineserver
timeout 60 "$WINE" wineboot -i </dev/null >/dev/null 2>&1 || true
timeout "$RUN_SECONDS" "$WINE" "$REAL" </dev/null >/dev/null 2>&1 || true
timeout "$RUN_SECONDS" "$WINE" "$REAL" </dev/null >/dev/null 2>&1 || true

phase_b_124=0
phase_b_neg_124=0
round=1
while [ "$round" -le "$ROUNDS" ]; do
    output=$(trial "$round")
    echo "$output"
    echo "$output" | grep -q "neg-junk.*exit=124" && phase_b_neg_124=$((phase_b_neg_124 + 1))
    echo "$output" | grep -q "neg-plain.*exit=124" && phase_b_neg_124=$((phase_b_neg_124 + 1))
    echo "$output" | grep -q "real-console-4k.*exit=124" && phase_b_124=$((phase_b_124 + 1))
    round=$((round + 1))
done

stop_wineserver

echo
echo "################################################################"
echo "### RESULT                                                     ###"
echo "################################################################"
echo "  phase A (cold start): real timed out $phase_a_124/$ROUNDS, negative controls timed out $phase_a_neg_124/$((ROUNDS * 2))"
echo "  phase B (warm):       real timed out $phase_b_124/$ROUNDS, negative controls timed out $phase_b_neg_124/$((ROUNDS * 2))"
echo
if [ "$phase_a_neg_124" -eq 0 ] && [ "$phase_b_neg_124" -eq 0 ]; then
    echo "VERDICT: exit 124 was produced only by the file that can execute."
    echo "         The timeout rule holds in this environment."
    exit 0
fi
if [ "$phase_b_neg_124" -eq 0 ]; then
    echo "VERDICT: 124 is NOT proof of execution on a cold start, but it is once the"
    echo "         environment is warm. A measurement that relies on it must warm up"
    echo "         first, and warm-up is a precondition of the method, not a nicety."
    exit 1
fi
echo "VERDICT: a file Wine cannot execute returns 124 even when the environment is warm."
echo "         Exit code alone is therefore NOT sound evidence of execution, and any"
echo "         conclusion resting on it needs a second, independent signal."
exit 1
