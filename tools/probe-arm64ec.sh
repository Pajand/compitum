#!/bin/sh
# Determine whether this machine's Wine can execute an ARM64EC binary, and report it.
#
# Usage:  sh tools/probe-arm64ec.sh <corpus-dir>
#
# Exit 0 means ARM64EC executed; exit 1 means it did not, and the caller should read that as
# "a build is required" rather than as a defect in the workflow.
#
# # Why the measurement is an exit code, when an earlier check in this project was told not to
#
# `tools/loopcheck.sh` measures CPU growth across two windows, because a hanging process also
# times out and an exit code therefore cannot distinguish *running* from *blocked*. That
# reasoning is sound, and it was learned the hard way.
#
# It cannot be used here. CPU growth is read from `/proc/<pid>/stat`, and under the container
# this runs in, a Wine-spawned process is visible only as the container's own interpreter --
# so every reading came back `+0`, including for a binary already proven to execute. The
# instrument, not the subject, was broken.
#
# The corpus gives a better signal. Every fixture's entry point is an infinite loop, so:
#
#   * a binary that LOADS runs forever  -> the timeout fires -> exit 124
#   * a binary that is REFUSED exits immediately -> some other code
#
# 124 versus "not 124" is a clean separation for these fixtures, and it needs no /proc access.
# The control below proves the method on a binary whose behaviour is already known, so the
# method is validated before it is trusted.
#
# # Every Wine invocation is guarded
#
# An earlier version hung for 43 minutes on work that should take five. Wine starts a
# `wineserver` daemon that detaches and inherits the step's file descriptors, keeping the step
# alive after the program it was started for has gone. So each call is bounded by `timeout`,
# gets `</dev/null` so it cannot wait on input, redirects to a file so it cannot hold the
# caller's stdout, and is followed by `wineserver -k`.

set -u

CORPUS="${1:-/tmp/corpus}"
SAMPLE="$CORPUS/real-console-4k.exe"
ARM64EC="$CORPUS/chpe-arm64ec.exe"
RUN_SECONDS=8

for required in "$SAMPLE" "$ARM64EC"; do
    if [ ! -f "$required" ]; then
        echo "::error::missing fixture: $required" >&2
        exit 1
    fi
done

# Runs a fixture and reports whether it was still running when the timeout fired.
# Prints 0 when the program executed, 1 when it did not, and the raw exit code on stderr.
executes() {
    binary="$1"
    set +e
    timeout "$RUN_SECONDS" "$WINE_BIN" "$binary" </dev/null >/tmp/run.log 2>&1
    rc=$?
    set -e
    # Stop the daemon, which would otherwise outlive its trial.
    timeout 20 "$WINE_BIN" wineserver -k </dev/null >/dev/null 2>&1 || true
    sleep 1
    echo "      raw exit code: $rc" >&2
    if [ "$rc" -eq 124 ]; then
        return 0    # still running when the timeout fired, therefore executing
    fi
    return 1        # exited on its own, so it did not load
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
# version.
# ---------------------------------------------------------------------------
WINE_BIN=""
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

    echo "    control (plain ARM64, known to execute):"
    if executes "$SAMPLE"; then
        echo "    ==> WORKS"
        echo
        break
    fi
    echo "    ==> cannot execute a plain ARM64 binary"
    WINE_BIN=""
done

if [ -z "$WINE_BIN" ]; then
    echo
    echo "VERDICT: no Wine entry point here can execute a plain ARM64 binary."
    echo "That is an environment result, not an ARM64EC verdict, and it means the"
    echo "measurement below cannot be trusted either way."
    exit 1
fi

echo "using: $WINE_BIN"
echo

# ---------------------------------------------------------------------------
# Step 2: the control, stated explicitly so the log shows it passed.
# ---------------------------------------------------------------------------
export WINEPREFIX=/tmp/wp-final
rm -rf "$WINEPREFIX"; mkdir -p "$WINEPREFIX"
WINEDLLOVERRIDES="mscoree,mshtml=" timeout 60 "$WINE_BIN" wineboot -i \
    </dev/null >/dev/null 2>&1 || true

echo "control   (plain ARM64)   :"
if ! executes "$SAMPLE"; then
    echo "VERDICT: the control did not execute, so ARM64EC cannot be judged from this run."
    exit 1
fi
echo "          control PASSED"

# ---------------------------------------------------------------------------
# Step 3: the actual question.
# ---------------------------------------------------------------------------
echo
echo "subject   (ARM64EC)       :"
if executes "$ARM64EC"; then
    echo
    echo "VERDICT: ARM64EC EXECUTES on this machine's Wine."
    echo "  $("$WINE_BIN" --version 2>&1 | head -1)"
    exit 0
fi

echo
echo "VERDICT: ARM64EC does NOT execute on this machine's Wine."
echo "  $("$WINE_BIN" --version 2>&1 | head -1)"
echo "  The control passed, so the environment is sound and this is a real limitation."
echo "  Building Wine from source is therefore justified; see"
echo "  docs/BUILDING-ARM64EC-WINE.md."
exit 1
