#!/bin/sh
# Close the loop: predict with COMPITUM, measure with Wine, compare.
#
# This is the demonstration the whole project exists to make. Every other test verifies a
# component; this one verifies the *claim* -- that COMPITUM's routing decision predicts what
# actually happens when a real ARM64 Windows binary is executed.
#
# ---------------------------------------------------------------------------
# How execution is detected, and why the obvious method is wrong
# ---------------------------------------------------------------------------
#
# The first version of this script treated a timeout exit code (124) as proof that the program
# ran. It is not. A program that **hangs** also times out, and that produced a false agreement:
# an x86-64 binary, which Wine on ARM64 cannot execute without FEX, was recorded as
# "executed" and therefore as a contradiction of the `fex_partial` prediction.
#
# Investigating that produced the actual discriminator. Claimed CPU time is not enough either,
# because Wine's first-run prefix initialisation (`rundll32 setupapi,InstallHinfSection`) burns
# over 1500 jiffies on its own -- far more than a blocked program. Measured in an
# already-initialised prefix, the two cases separate cleanly:
#
#     ARM64 binary, infinite loop   : +456 jiffies in 4 s   -> executing
#     x86-64 binary, cannot run     :  +18 jiffies in 4 s   -> not executing
#
# So this script measures **CPU growth across two windows**. A program that is running
# accumulates CPU steadily; one that is blocked, refused or parked on a dialog does not.
# The exit code is still reported, because it explains *why* something did not run, but it is
# no longer the evidence.
#
# Usage:  sh tools/loopcheck.sh <path-to-compitum> <path-to-corpus-dir>

set -u

COMPITUM="${1:-/root/compitum}"
CORPUS="${2:-/root/corpus}"
WINEPREFIX="${WINEPREFIX:-/tmp/wineprefix-loop}"
# The Wine to measure with. Honour an explicit override, because a freshly built Wine usually
# lives outside PATH and using the wrong one would silently measure the wrong thing — the exact
# class of mistake this script's history is full of.
WINE="${WINE:-wine}"
export WINEPREFIX
export WINEDEBUG=-all

# Jiffies of CPU growth, over a four-second window, below which a process is not considered to
# be executing. The measured separation is 18 versus 456, so this sits far from both.
CPU_THRESHOLD=150

if [ ! -x "$COMPITUM" ]; then
    echo "compitum not executable at $COMPITUM" >&2
    exit 1
fi
if [ ! -d "$CORPUS" ]; then
    echo "corpus not found at $CORPUS" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Wine's first-run prefix setup dominates any measurement taken in a fresh
# prefix, so it is paid once, up front, and the prefix is reused afterwards.
# ---------------------------------------------------------------------------
if [ ! -d "$WINEPREFIX" ] || [ -z "$(ls -A "$WINEPREFIX" 2>/dev/null)" ]; then
    "$WINE" --version 2>/dev/null | sed 's/^/wine: /'
    echo "initialising the Wine prefix once (its setup cost would otherwise swamp the measurement)"
    "$WINE" wineboot -i >/dev/null 2>&1
    "$WINE" wineserver -k >/dev/null 2>&1
    sleep 1
fi

# Sums utime+stime for every process whose command line mentions the given name.
cpu_jiffies() {
    total=0
    for proc in /proc/[0-9]*; do
        cmd=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null) || continue
        case "$cmd" in
            *"$1"*)
                stat=$(cat "$proc/stat" 2>/dev/null) || continue
                rest=${stat#*) }
                set -- $rest
                total=$(( total + ${12:-0} + ${13:-0} ))
                ;;
        esac
    done
    echo "$total"
}

agree=0
disagree=0
failures=0
rows=""

printf '%-24s %-18s %-14s %s\n' "binary" "predicted" "observed" "verdict"
printf '%-24s %-18s %-14s %s\n' "------------------------" "------------------" "--------------" "-------"

for binary in "$CORPUS"/*.exe; do
    [ -e "$binary" ] || continue
    name=$(basename "$binary")

    # ---- the prediction ----
    # `--no-record`: this script is a demonstration and must not quietly grow the ledger. The
    # ledger is for real observations.
    #
    # The pattern tolerates arbitrary whitespace around the colon, because the CLI emits
    # pretty-printed JSON and an exact-spacing pattern silently failed to match once already.
    prediction=$("$COMPITUM" verify "$binary" --backends wine,fex --no-record --json 2>/dev/null \
        | sed -n 's/.*"route"[[:space:]]*:[[:space:]]*"\([a-z_]*\)".*/\1/p' | head -1)

    if [ -z "$prediction" ]; then
        echo "FATAL: could not read a route for $name; the CLI produced no parseable decision" >&2
        failures=$((failures + 1))
        prediction="EXTRACTION_FAILED"
    fi

    # ---- the measurement: CPU growth across two windows ----
    "$WINE" "$binary" >/dev/null 2>&1 &
    sleep 4
    first=$(cpu_jiffies "$name")
    sleep 4
    second=$(cpu_jiffies "$name")
    growth=$(( second - first ))
    "$WINE" wineserver -k >/dev/null 2>&1
    pkill -f "$name" >/dev/null 2>&1
    sleep 1

    if [ "$growth" -ge "$CPU_THRESHOLD" ]; then
        observed="executing(+$growth)"
    else
        observed="not-running(+$growth)"
    fi

    # ---- the comparison ----
    # The prediction is about the route; the observation is about whether execution happened.
    # They agree when a route claiming native execution executes, and when a route naming a
    # backend this environment lacks fails to execute.
    case "$prediction" in
        native|pick_native_slice)
            if [ "$growth" -ge "$CPU_THRESHOLD" ]; then
                verdict="AGREE"; agree=$((agree + 1))
            else
                verdict="DISAGREE"; disagree=$((disagree + 1))
            fi
            ;;
        fex_partial|box64_full|fex_full|wow64|refused)
            # These name a backend this environment does not have, so failing to execute
            # confirms the prediction rather than contradicting it.
            if [ "$growth" -ge "$CPU_THRESHOLD" ]; then
                verdict="DISAGREE"; disagree=$((disagree + 1))
            else
                verdict="AGREE"; agree=$((agree + 1))
            fi
            ;;
        *)
            verdict="no-prediction"
            ;;
    esac

    rows="$rows$name|$prediction|$observed|$verdict
"
    printf '%-24s %-18s %-14s %s\n' "$name" "$prediction" "$observed" "$verdict"
done

echo
echo "agreements: $agree    disagreements: $disagree    extraction failures: $failures"
echo "threshold: $CPU_THRESHOLD jiffies of CPU growth over 4 s"
echo

# A check that passes having verified nothing is worse than no check: it converts an absence of
# evidence into apparent evidence. This guard exists because an earlier version of this script
# printed "every prediction matched observation" while having made zero predictions.
if [ "$failures" -gt 0 ]; then
    echo "VERDICT: $failures prediction(s) could not be read; this run verified nothing"
    exit 1
fi

if [ "$agree" -eq 0 ]; then
    echo "VERDICT: no comparisons were made, so nothing was verified"
    exit 1
fi

if [ "$disagree" -gt 0 ]; then
    echo "VERDICT: the routing prediction did not match observation for $disagree file(s)"
    exit 1
fi

echo "VERDICT: all $agree prediction(s) matched observation"
exit 0
