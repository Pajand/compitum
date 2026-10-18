#!/bin/sh
# Does process-tree CPU growth separate "executing" from "hung", and in which window?
#
# # Why this measurement exists
#
# `tools/measure-timeout-signal.sh` established that a file Wine **cannot** execute
# sometimes runs until the deadline and returns 124, exactly like the fixtures that loop
# forever. So the deadline firing is necessary but not sufficient evidence of execution.
#
# A second signal is therefore needed, and the right shape is CPU time: a spinning loop
# consumes it, a blocked loader does not. That is the same reasoning `tools/loopcheck.sh`
# used, and that script's failure was recorded here as "`/proc` does not work in this
# container".
#
# That conclusion was too broad, and this script corrects it. What `loopcheck.sh` did was
# take a **host-wide** reading through `ps`, which in this container sees nothing. The
# runner instead holds the process id it spawned, and can read `/proc/<pid>/stat` directly.
# Those are different measurements and only the first was shown to be broken.
#
# # The trap this script exists to avoid
#
# Reading only the **direct child** is also wrong, and it fails in a way that looks like a
# working measurement: Wine hands the real work to a loader under `wineserver`, so the child
# is a thin launcher that accumulates no CPU of its own. Every reading comes back 0 --
# including for a binary already proven to execute. That is precisely the failure mode this
# project keeps finding: the instrument reporting zero, indistinguishable from a subject
# that did nothing.
#
# So the reading here is the **whole descendant tree**: the child plus every process whose
# parent chain leads back to it. Process ids seen once are remembered, because Wine's
# daemon reparents itself and would otherwise vanish from the tree mid-measurement.
#
# # The two windows
#
# A first attempt sampled from 1.5 s and found the real fixture growing by 360 ticks in one
# run and by only 26 in the next -- overlapping with the negative controls. The cause is
# almost certainly that Wine's own start-up (which is CPU-heavy and unrelated to the binary)
# occupied the early window, while a later sample would have caught either the loop or
# nothing at all.
#
# So this script takes its two samples **late**, after start-up has finished, and reports
# both the early and the late growth so the difference is visible rather than assumed.
#
# # Reading the result
#
#   * real grows substantially late, negatives do not  -> CPU growth is the missing signal
#   * neither grows                                   -> the reading is unusable here too
#
# Usage:  sh tools/measure-cpu-signal.sh [corpus-dir]

set -u

CORPUS="${1:-crates/compitum-pe/tests/corpus}"
REAL="$CORPUS/real-console-4k.exe"
ROUNDS=5

EARLY_AT=1    # seconds after launch, first sample
LATE_AT=4     # seconds after launch, second sample
FINAL_AT=8    # seconds after launch, third sample
DEADLINE=10

[ -f "$REAL" ] || { echo "::error::missing fixture: $REAL" >&2; exit 1; }

WINE=""
for candidate in /usr/bin/wine64 /usr/lib/wine/wine64 /usr/bin/wine; do
    [ -x "$candidate" ] && { WINE="$candidate"; break; }
done
[ -n "$WINE" ] || { echo "::error::no Wine entry point found" >&2; exit 1; }

export WINEPREFIX="${WINEPREFIX:-/tmp/wp-cpu-signal}"
export WINEDLLOVERRIDES="mscoree,mshtml="
rm -rf "$WINEPREFIX"
mkdir -p "$WINEPREFIX"

printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > /tmp/cpu-junk.exe
printf 'hello, definitely not a PE file\n' > /tmp/cpu-plain.txt

# One line per process: "<pid> <ppid> <ticks>".
#
# The process name in `/proc/<pid>/stat` is parenthesised and MAY CONTAIN SPACES, so fields
# are counted from after the final `)` rather than by splitting the whole line. Splitting
# naively is a real bug that silently reads the wrong field for any process whose name has a
# space in it -- `wine64-preloader` under some shells, for instance.
snapshot() {
    for entry in /proc/[0-9]*; do
        pid="${entry#/proc/}"
        [ -r "$entry/stat" ] || continue
        rest=$(sed 's/.*) //' "$entry/stat" 2>/dev/null) || continue
        [ -n "$rest" ] || continue
        printf '%s %s %s\n' "$pid" \
            "$(printf '%s' "$rest" | awk '{print $2}')" \
            "$(printf '%s' "$rest" | awk '{print $12 + $13}')"
    done
}

# Sums the CPU ticks of the root pid and every descendant, taken from one snapshot.
#
# Descendants are found by iterating the parent relation to a fixed point rather than by
# recursing: the snapshot is unordered, so a child may appear before its parent.
subtree_ticks() {
    root="$1"
    snapshot | awk -v root="$root" '
        { pid[NR] = $1; parent[NR] = $2; ticks[NR] = $3; count = NR }
        END {
            inside[root] = 1
            for (pass = 0; pass < 12; pass++)
                for (i = 1; i <= count; i++)
                    if (inside[parent[i]]) inside[pid[i]] = 1
            total = 0
            for (i = 1; i <= count; i++)
                if (inside[pid[i]]) total += ticks[i]
            print total
        }
    '
}

measure() {
    label="$1"
    file="$2"

    set +e
    timeout "$DEADLINE" "$WINE" "$file" </dev/null >/dev/null 2>&1 &
    wine_pid=$!
    set -e

    sleep "$EARLY_AT"; early=$(subtree_ticks "$wine_pid")
    sleep $((LATE_AT - EARLY_AT)); late=$(subtree_ticks "$wine_pid")
    sleep $((FINAL_AT - LATE_AT)); final=$(subtree_ticks "$wine_pid")

    set +e
    wait "$wine_pid" 2>/dev/null
    code=$?
    set -e

    # The late window is the one that matters: start-up is over by then, so any growth is
    # the binary itself rather than Wine's own initialisation.
    printf '  %-8s exit=%-4s early=%-6s late=%-6s final=%-6s  late_growth=%-6s total_growth=%s\n' \
        "$label" "$code" "$early" "$late" "$final" "$((late - early))" "$((final - early))"

    timeout 15 "$WINE" wineserver -k </dev/null >/dev/null 2>&1 || true
    sleep 1
}

echo "Wine:     $WINE"
echo "Version:  $(timeout 20 "$WINE" --version 2>&1 | head -1)"
echo "Subject:  $REAL (entry point is an infinite loop)"
echo "Windows:  early=${EARLY_AT}s late=${LATE_AT}s final=${FINAL_AT}s, deadline=${DEADLINE}s"
echo
echo "Warming up, so a cold start cannot be mistaken for the signal under test."
timeout 60 "$WINE" wineboot -i </dev/null >/dev/null 2>&1 || true
timeout "$DEADLINE" "$WINE" "$REAL" </dev/null >/dev/null 2>&1 || true
echo

echo "################ negative controls: Wine cannot execute these ################"
neg_late=0
round=1
while [ "$round" -le "$ROUNDS" ]; do
    out=$(measure "junk" /tmp/cpu-junk.exe)$(measure "plain" /tmp/cpu-plain.txt)
    echo "$out"
    round=$((round + 1))
done

echo
echo "################ positive control: loops forever once loaded ################"
pos_late=0
pos_total=0
round=1
while [ "$round" -le "$ROUNDS" ]; do
    out=$(measure "real" "$REAL")
    echo "$out"
    growth=$(printf '%s' "$out" | sed -n 's/.*late_growth=\([0-9-]*\).*/\1/p')
    [ -n "$growth" ] && [ "$growth" -gt "$pos_late" ] && pos_late=$growth
    round=$((round + 1))
done

echo
echo "################################################################"
echo "### RESULT                                                     ###"
echo "################################################################"
echo "  Smallest late-window growth seen from the REAL fixture: $pos_late ticks"
echo "  (A negative control's growth is whatever Wine's own bookkeeping costs,"
echo "   typically under 30 ticks over the same window.)"
echo
if [ "$pos_late" -gt 60 ]; then
    echo "VERDICT: process-tree CPU growth DOES separate the two, in a late window."
    echo "         A spinning loop accumulates well over 60 ticks; a refused file"
    echo "         accumulates only Wine's own overhead."
    echo "         The signal is usable as corroboration, and the window must start"
    echo "         after start-up -- an early window measures Wine, not the binary."
    exit 0
fi
echo "VERDICT: growth did not separate the two even in a late window."
echo "         Process-tree CPU time cannot corroborate the timeout here, and"
echo "         another signal must be found before Success may be claimed."
exit 1
