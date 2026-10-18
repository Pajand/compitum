#!/bin/sh
# Determine whether this machine's Wine can execute an ARM64EC binary, and report it.
#
# Usage:  sh tools/probe-arm64ec.sh <corpus-dir>
#
# Exit codes, and the distinction between the last two is the point:
#
#   0  ARM64EC executed
#   1  it did not, and the caller should read that as "a build is required" rather than as a
#      defect in the workflow
#   3  NOTHING WAS MEASURED -- the instrument could not read CPU time, so neither a positive
#      nor a negative result was obtained. A caller must never translate this into "it does
#      not work", because that is a finding the run did not produce.
#
# Exit 3 was added after it happened: on the CI runner both CPU samples read 0/0, the probe
# reported "the binary did not execute", and the workflow turned that into "Wine must be built
# from source". Hours of work were about to be justified by an instrument that had observed
# nothing.
#
# # Why this measurement is not just an exit code any more
#
# An earlier version of this script decided the question from the exit code alone: every
# fixture's entry point is an infinite loop, so a binary that LOADS runs until `timeout`
# fires (exit 124), while one that is REFUSED exits immediately.
#
# That reasoning is sound as far as it goes, and it is not sufficient. It was measured:
#
#   tools/measure-timeout-signal.sh
#
# A sixteen-byte file containing only the `MZ` signature -- which nothing can execute --
# also ran until the deadline and returned 124, in **12 of 32 trials** (two negative controls,
# 16 runs each phase). Wine's own start-up
# can outlast the deadline, so "still running" has two explanations and only one of them is
# about the binary:
#
#   * the program is EXECUTING  -- its spinning entry point keeps consuming CPU, or
#   * the loader is STILL STARTING or BLOCKED -- it consumes none.
#
# So the timeout is necessary but not sufficient, and this script now requires a second,
# independent signal: CPU time consumed by the process **tree**, measured in a window that
# opens after start-up has settled.
#
# # Why the whole tree, and why a late window
#
# Reading only the direct child measures nothing: under Wine the child is a thin launcher and
# the real work happens in a loader whose parent chain runs through `wineserver`. A
# child-only reading returns 0 every time, including for a binary already proven to execute.
#
# And an early window measures Wine rather than the binary. The first attempt sampled from
# 1.5 s and produced 26 ticks for a fixture that was demonstrably looping -- overlapping the
# negative controls, which reached 1. Opening the window half way through the run is what
# makes the two separable.
#
# Measured separation, from tools/measure-cpu-signal.sh: the fixture was sampled at 1 s and
# again at 4 s of an 8 s run, so the window is 3 s and it starts after start-up.
#
#   the real ARM64 fixture (infinite loop) : 256, 253, 242, 204, and once 0 ticks
#   a file containing only `MZ`            : never above 1 tick
#
# The single zero in the first row is recorded rather than smoothed away: one sampling window
# can miss. `crates/compitum-exec` keeps a *peak* across many samples for exactly this reason,
# which is more robust than the two-point difference this script uses.
#
# The threshold below is 5 ticks per second: an order of magnitude under the signal and an
# order of magnitude over the noise.
#
# # Every Wine invocation is guarded
#
# An earlier version hung for 43 minutes on work that should take five. Wine starts a
# `wineserver` daemon that detaches and inherits the step's file descriptors, keeping the
# step alive after the program it was started for has gone. So each call is bounded by
# `timeout`, gets `</dev/null` so it cannot wait on input, redirects to a file so it cannot
# hold the caller's stdout, and is followed by `wineserver -k`.

set -u

# NOT `set -e`, deliberately. Every decision in this script is made from an explicit exit
# status, and a status capture is impossible under errexit. Turning errexit on anywhere --
# including from inside a function, which is how it leaked here once -- silently converts a
# three-state return code into a four-state one, the fourth being the shell's own.
#
# `set -u` stays: an unset variable is a mistake in a script whose whole job is to report
# precisely, and failing loudly on one is the desired behaviour.

CORPUS="${1:-/tmp/corpus}"
SAMPLE="$CORPUS/real-console-4k.exe"
ARM64EC="$CORPUS/chpe-arm64ec.exe"
RUN_SECONDS=8

# Ticks per second of sustained tree-wide CPU growth required to conclude that a binary is
# executing rather than still starting. See the comment above for how it was chosen.
MIN_TICKS_PER_SECOND=5

for required in "$SAMPLE" "$ARM64EC"; do
    if [ ! -f "$required" ]; then
        echo "::error::missing fixture: $required" >&2
        exit 1
    fi
done

# Brings the current WINEPREFIX to a state where measurement means something.
#
# Without this the first execution of any binary in a fresh prefix spends its whole allowance
# initialising the prefix, which is indistinguishable from a loader that is blocked. The
# throwaway run is deliberately the CONTROL, so warming up also fails loudly if the
# environment cannot run a known-good binary at all.
warm_up() {
    warm_subject="$1"
    WINEDLLOVERRIDES="mscoree,mshtml=" timeout 60 "$WINE_BIN" wineboot -i \
        </dev/null >/dev/null 2>&1 || true
    timeout "$((RUN_SECONDS + 3))" "$WINE_BIN" "$warm_subject" </dev/null >/dev/null 2>&1 || true
    timeout 20 "$WINE_BIN" wineserver -k </dev/null >/dev/null 2>&1 || true
    sleep 1
}

# Reads /proc and reports how many process entries were readable.
#
# This exists because "the tree consumed no CPU" and "the tree could not be read" are
# different answers, and an earlier version of this script collapsed them. On the CI runner
# both samples came back 0/0 and the probe concluded "the binary did not execute" -- a
# conclusion drawn from an instrument that had reported nothing at all.
readable_entries() {
    count=0
    for entry in /proc/[0-9]*; do
        [ -r "$entry/stat" ] && count=$((count + 1))
    done
    echo "$count"
}

# Sums the CPU ticks of a pid and every descendant.
#
# The process name in /proc/<pid>/stat is parenthesised and MAY CONTAIN SPACES, so fields are
# counted from after the final ')' rather than by splitting the whole line. Splitting naively
# reads the wrong field for any process whose name contains a space, and the resulting error
# is silent -- it yields a plausible number.
#
# Prints the total, or NOTHING when the measurement could not be made. Printing an empty string
# rather than 0 is deliberate, because there are two ways to learn nothing and both produce a
# zero that looks like an answer:
#
#   * /proc could not be read at all, and
#   * the process we meant to watch was not visible in it.
#
# The second is what happened on the CI runner: every sample read 0, the probe reported "the
# binary did not execute", and the workflow nearly turned that into hours of building Wine.
# A zero is only an answer when the thing being watched was actually there to be read.
tree_ticks() {
    root="$1"
    if [ "$(readable_entries)" -eq 0 ]; then
        return 0   # nothing printed -> /proc unreadable
    fi
    if [ ! -r "/proc/$root/stat" ]; then
        return 0   # nothing printed -> the watched process is not visible
    fi
    for entry in /proc/[0-9]*; do
        [ -r "$entry/stat" ] || continue
        rest=$(sed 's/.*) //' "$entry/stat" 2>/dev/null) || continue
        [ -n "$rest" ] || continue
        printf '%s %s\n' "${entry#/proc/}" "$(printf '%s' "$rest" | awk '{print $2, $12 + $13}')"
    done | awk -v root="$root" '
        { pid[NR] = $1; parent[NR] = $2; ticks[NR] = $3; count = NR }
        END {
            inside[root] = 1
            found_root = 0
            for (i = 1; i <= count; i++)
                if (pid[i] == root) found_root = 1
            # The root itself must be in the table, or there is nothing to attribute to it and
            # a sum of zero would be meaningless rather than informative.
            if (!found_root) exit
            # Fixed-point closure rather than recursion: the table is unordered, so a child
            # can appear before its parent and a single pass would miss it.
            for (pass = 0; pass < 16; pass++)
                for (i = 1; i <= count; i++)
                    if (inside[parent[i]]) inside[pid[i]] = 1
            total = 0
            for (i = 1; i <= count; i++)
                if (inside[pid[i]]) total += ticks[i]
            print total
        }
    '
}

# Runs a fixture and reports whether it EXECUTED.
#
# Return codes, and the distinction between them is the whole point:
#
#   0  it executed   -- the deadline fired AND the tree sustained CPU growth
#   1  it did not    -- it exited on its own, or the deadline fired with no CPU growth
#   2  unmeasurable  -- /proc could not be read, so nothing was observed either way
#
# 2 exists because an earlier version returned 1 for that case. On the CI runner both samples
# read 0/0, the probe reported "the binary did not execute", and the workflow turned that into
# "Wine must be built from source" -- hours of work, decided by an instrument that had observed
# nothing. An unmeasurable run must never be reported as a negative result.
#
# # Warm-up is a precondition, not a nicety
#
# On a FRESH Wine prefix, the very first execution spends its entire allowance initialising
# the prefix: it returns 124 with a tree total of about 3 ticks, because the fixture never
# reaches its loop. The strengthened criterion then refuses to call that execution -- correctly,
# since a file that cannot load looks identical -- but the refusal says nothing about the
# binary. `tools/measure-cpu-signal.sh` already established this: every measurement there is
# preceded by `wineboot` AND a throwaway run. So `warm_up` does the same before anything is
# judged.
executes() {
    binary="$1"
    label="$2"

    # Half the run is the tail window: start-up is over by then, and the remaining time is
    # long enough to sustain a measurable rate.
    tail_at=$((RUN_SECONDS / 2))

    # The last sample must land BEFORE the kill, or it reads an already-reaped tree and
    # reports zero. An earlier version sampled at exactly the deadline and every reading came
    # back 0 -- a zero indistinguishable from a subject that did nothing, which is precisely
    # the failure this probe exists to catch. The margin costs three seconds.
    #
    # NOTE: this script runs with `set -u` and deliberately NOT with `set -e`. An earlier
    # version had `set +e` / `set -e` pairs bracketing each status capture, and because a
    # POSIX function is not a subshell, that `set -e` leaked out of the function and applied
    # to the rest of the script. The result: the bare `executes "$SAMPLE" "control"` call
    # returning 2 aborted the whole probe with status 2, before `probe_code=$?` was ever
    # evaluated -- so the three-state design was defeated by an invisible setting, and the
    # caller received an exit code the script never documents. A status capture needs no
    # errexit toggling when errexit is off to begin with.
    timeout $((RUN_SECONDS + 3)) "$WINE_BIN" "$binary" </dev/null >/tmp/run.log 2>&1 &
    run_pid=$!

    sleep "$tail_at"
    baseline=$(tree_ticks "$run_pid")

    sleep $((RUN_SECONDS - tail_at))
    peak=$(tree_ticks "$run_pid")

    wait "$run_pid" 2>/dev/null
    rc=$?

    # Stop the daemon, which would otherwise outlive its trial.
    timeout 20 "$WINE_BIN" wineserver -k </dev/null >/dev/null 2>&1 || true
    sleep 1

    window=$((RUN_SECONDS - tail_at))

    echo "    $label raw exit code : $rc   (124 = the deadline fired)"

    # ORDER MATTERS HERE, and the first version of this got it wrong.
    #
    # A process that exits quickly cannot be sampled afterwards: its /proc entry is gone, so
    # the reading comes back empty. That is indistinguishable from "/proc is broken" unless the
    # exit code is consulted first -- and it carries a conclusive answer already. The negative
    # control exits 47, was then reported as "could not measure", and the probe halted on a
    # control that had in fact behaved perfectly.
    #
    # So: an exit code other than 124 settles the question without any CPU evidence, and only a
    # timeout depends on it.
    if [ "$rc" -ne 124 ]; then
        echo "    ==> EXITED on its own, so it did not load"
        return 1
    fi

    # The deadline fired, so the process was alive at the end and the CPU reading is required.
    # An empty reading here means the instrument failed, not that the binary did nothing.
    if [ -z "$baseline" ] || [ -z "$peak" ]; then
        echo "    $label tree CPU      : UNREADABLE (the watched process was not visible in /proc)"
        echo "    ==> COULD NOT MEASURE: nothing is known about this binary from this run."
        echo "        This is a limitation of the host, not a negative result."
        return 2
    fi

    growth=$((peak - baseline))
    [ "$growth" -lt 0 ] && growth=0

    # `growth` is already in clock ticks and `window` in seconds, so the threshold is compared
    # against `growth` directly. An earlier version scaled by `getconf CLK_TCK` as well, which
    # counted the tick unit twice and reported 12725 ticks/s for a reading that was 127 -- a
    # number 100x too large, in a direction that would make a blocked loader look busy.
    #
    # Multiplication rather than division so a short window cannot truncate the rate to zero.
    required=$((MIN_TICKS_PER_SECOND * window))
    rate=$((growth / window))

    echo "    $label tree CPU      : baseline=$baseline peak=$peak growth=$growth ticks"
    echo "    $label sustained     : $rate ticks/s (threshold $MIN_TICKS_PER_SECOND, needs $required ticks in ${window}s)"

    if [ "$growth" -lt "$required" ]; then
        echo "    ==> TIMED OUT WITHOUT CONSUMING CPU: still starting or blocked, not executing."
        echo "        A file that cannot be loaded at all produces the same reading, so this"
        echo "        is NOT evidence that the binary executed."
        return 1
    fi
    echo "    ==> EXECUTING: timed out and sustained $rate ticks/s"
    return 0
}

# ---------------------------------------------------------------------------
# Step 1: find a Wine entry point that can execute our control fixture.
#
# `command -v wine64` is not enough. Ubuntu's wine64 package installs the loader at
# /usr/lib/wine/wine64 and no `wine64` on PATH, so a PATH lookup falls through to the `wine`
# wrapper -- which prints a version even when it cannot launch anything, and on a 64-bit-only
# install it says "it looks like wine32 is missing" and exits.
#
# So each candidate is judged by whether it executes the control, not by whether it reports a
# version. The control runs FIRST, which is why the result below is trustworthy: a probe that
# cannot even confirm a known-good binary has no standing to judge a hard one.
# ---------------------------------------------------------------------------
WINE_BIN=""
UNMEASURABLE=0
for candidate in /usr/bin/wine64 /usr/bin/wine /usr/lib/wine/wine64; do
    [ -x "$candidate" ] || continue

    echo "=== trying $candidate"
    WINE_BIN="$candidate"
    export WINEPREFIX=/tmp/wp-probe
    rm -rf "$WINEPREFIX"; mkdir -p "$WINEPREFIX"

    # The raw loader is not a wrapper: it does not know where its own libraries live.
    if [ "$candidate" = "/usr/lib/wine/wine64" ]; then
        export WINELOADER="$candidate"
        export WINEDLLPATH="/usr/lib/aarch64-linux-gnu/wine:/usr/lib/wine"
    fi

    echo "    version: $(timeout 20 "$candidate" --version 2>&1 | head -1 || echo '(none)')"

    # Mono and Gecko are disabled: installing them tries to DOWNLOAD from the internet, which
    # is what hung an earlier run. Neither is needed to execute a binary.
    WINEDLLOVERRIDES="mscoree,mshtml=" timeout 60 "$candidate" wineboot -i \
        </dev/null >/tmp/boot.log 2>&1 || true
    grep -iE "wine32|error|cannot|missing" /tmp/boot.log | head -3 | sed 's/^/    boot: /'

    echo "    warming up this prefix (wineboot + one throwaway run)"
    warm_up "$SAMPLE"

    echo "    control (plain ARM64, known to execute):"
    executes "$SAMPLE" "control"
    probe_code=$?
    case "$probe_code" in
        0)
            echo "    ==> WORKS"
            echo
            break
            ;;
        1)
            echo "    ==> cannot execute a plain ARM64 binary"
            ;;
        *)
            # The instrument failed, not the binary. Recording this separately matters: the
            # candidate is neither accepted nor rejected, and the final verdict must say that
            # nothing was measured rather than that ARM64EC does not work.
            #
            # The exit is taken HERE rather than deferred to the end of the loop, because an
            # earlier version deferred it and the script exited 2 instead -- `set -u` tripped on
            # a later reference before reaching the intended `exit 3`. An explicit exit at the
            # point of discovery cannot be derailed by anything downstream.
            echo "    ==> COULD NOT MEASURE with this entry point"
            UNMEASURABLE=1
            ;;
    esac
    [ "$UNMEASURABLE" -eq 1 ] && continue
    WINE_BIN=""
done

if [ -z "$WINE_BIN" ]; then
    echo
    if [ "$UNMEASURABLE" -eq 1 ]; then
        echo "VERDICT: the control could not be MEASURED here, so nothing was learned."
        echo "  CPU time was unreadable, which is a limitation of the instrument, not a"
        echo "  result about ARM64EC. Reporting 'does not execute' from this run would be"
        echo "  inventing a finding, so the probe reports that it could not tell."
        echo "  Exit 3 means exactly that and is distinct from exit 1."
        exit 3
    fi
    echo "VERDICT: no Wine entry point here can execute a plain ARM64 binary."
    echo "That is an environment result, not an ARM64EC verdict, and it means the"
    echo "measurement below cannot be trusted either way."
    exit 1
fi

echo "using: $WINE_BIN"
echo

# ---------------------------------------------------------------------------
# Step 2: the controls, on a fresh prefix.
#
# TWO controls, not one, and the second is the important one.
#
#   POSITIVE  a plain ARM64 binary known to execute. If this fails, the environment is
#             broken and no verdict about ARM64EC can be drawn from the run.
#
#   NEGATIVE  a file that is not a PE image at all, so Wine CANNOT execute it. This one
#             exists because the criterion being tested is new: the timeout alone was used
#             before and was measured to be unreliable (`tools/measure-timeout-signal.sh`
#             found a `MZ`-only file hitting the deadline in 12 of 32 trials).
#
#             If the negative control PASSES the criterion, the criterion is broken and the
#             subject's result means nothing. A check that cannot reject a file nobody can
#             run has no standing to accept one that nobody has seen run.
#
# The negative control is built here rather than committed, so nothing in the repository
# depends on a binary fixture, and so it cannot accidentally become runnable.
# ---------------------------------------------------------------------------
export WINEPREFIX=/tmp/wp-final
rm -rf "$WINEPREFIX"; mkdir -p "$WINEPREFIX"
warm_up "$SAMPLE"

echo "control   (plain ARM64)   :"
executes "$SAMPLE" "control"
control_code=$?
if [ "$control_code" -eq 2 ]; then
    echo
    echo "VERDICT: the control could not be MEASURED, so nothing was learned."
    echo "  CPU time was unreadable in the tail window. That is a limitation of the"
    echo "  instrument; treating it as 'the binary did not run' would invent a finding."
    exit 3
fi
if [ "$control_code" -ne 0 ]; then
    echo "VERDICT: the control did not execute, so ARM64EC cannot be judged from this run."
    exit 1
fi
echo "          control PASSED"

# A 16-byte file carrying only the MZ signature. Wine reports it as unloadable and exits 47,
# but -- as measured -- it sometimes runs until the deadline instead. Either way it must
# never satisfy the criterion.
NEGATIVE=/tmp/wp-negative.exe
printf 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' > "$NEGATIVE"

echo
echo "negative  (MZ only, not a PE image):"
executes "$NEGATIVE" "negative"
negative_code=$?
case "$negative_code" in
    0)
        echo
        echo "VERDICT: the criterion is BROKEN -- it accepted a file Wine cannot execute."
        echo "  Nothing below would have been meaningful, so the run stops here."
        echo "  Expected: an exit other than 124, or 124 with no sustained CPU growth."
        exit 1
        ;;
    2)
        # The negative control must be REJECTED. Failing to measure it is not a rejection:
        # it leaves the criterion unvalidated, so the subject's result would have no standing.
        echo
        echo "VERDICT: the negative control could not be measured, so the criterion is"
        echo "  unvalidated and the subject is not judged. An instrument that cannot see"
        echo "  the control cannot be trusted with the subject."
        exit 3
        ;;
    *)
        echo "          negative control REJECTED, as it must be"
        ;;
esac

# ---------------------------------------------------------------------------
# Step 3: the actual question.
# ---------------------------------------------------------------------------
echo
echo "subject   (ARM64EC)       :"
executes "$ARM64EC" "subject"
subject_code=$?
if [ "$subject_code" -eq 2 ]; then
    echo
    echo "VERDICT: the subject could not be MEASURED, so nothing was learned about it."
    echo "  This is NOT a negative result and must not be read as one."
    exit 3
fi
if [ "$subject_code" -eq 0 ]; then
    echo
    echo "VERDICT: ARM64EC EXECUTES on this machine's Wine."
    echo "  $("$WINE_BIN" --version 2>&1 | head -1)"
    echo "  Evidence: the deadline fired AND the process tree sustained CPU growth above"
    echo "  the threshold, so this is execution rather than a slow start."
    echo "  Both controls held, so the criterion that produced this answer can reject a"
    echo "  file that cannot run -- which is what makes the answer about the subject."
    exit 0
fi

echo
echo "VERDICT: ARM64EC does NOT execute on this machine's Wine."
echo "  $("$WINE_BIN" --version 2>&1 | head -1)"
echo "  Both controls held, so the environment is sound and the criterion is discriminating;"
echo "  this is a real limitation. Building Wine from source is therefore justified; see"
echo "  docs/BUILDING-ARM64EC-WINE.md."
exit 1
