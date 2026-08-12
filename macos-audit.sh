#!/bin/bash
#
# macos-audit.sh — comprehensive, read-only macOS system audit collector
#
# PURPOSE
#   Collect a very large, well-structured snapshot of a Mac's configuration,
#   security posture, management (MDM/Platform SSO) state, network, storage,
#   power, processes, software and recent logs into a single Markdown report
#   that can be handed to a human or an AI assistant for diagnosis.
#
# SAFETY MODEL (read-only)
#   * The ONLY thing this script writes is its own report file (and a temp
#     working directory under $TMPDIR that is removed on exit).
#   * No setting is changed, no file is moved/deleted, no service is started,
#     stopped or restarted, no cache is cleared, no repair is attempted.
#   * Only query/getter subcommands are used. Anything that mutates state
#     (e.g. `softwareupdate -i`, `fdesetup enable`, `sysadminctl -addUser`,
#     `pmset -a`, `systemsetup -set*`, `jamf policy`, `profiles -R`) is
#     deliberately absent.
#   * `sudo` is used non-interactively only (`sudo -n`) unless you pass
#     --sudo, and even then only for read-only commands.
#   * `osascript` / AppleEvents are never used, so no Automation or Full Disk
#     Access consent dialogs are triggered by this script.
#   * Optional outbound probes (DNS/ping/HTTPS/TLS) only touch well-known
#     Apple, Cloudflare and Microsoft endpoints and can be disabled with
#     --no-network.
#
# USAGE
#   bash macos-audit.sh                 # normal run, report on the Desktop
#   sudo bash macos-audit.sh            # same, plus privileged read-only data
#   bash macos-audit.sh --sudo          # prompt once for sudo, then collect
#   bash macos-audit.sh --stdout > a.md # write report to stdout
#   bash macos-audit.sh --help
#
# Requires bash 3.2+ (the stock /bin/bash on macOS). No dependencies beyond
# what ships with macOS.
#

VERSION="1.0.0"
SCRIPT_NAME="macos-audit.sh"

# ---------------------------------------------------------------------------
# Shell options
# ---------------------------------------------------------------------------
# Deliberately NOT using `set -e`: probing commands are expected to fail and
# a non-zero exit is itself useful data.
set -u
set -o pipefail 2>/dev/null || true

umask 077

# ---------------------------------------------------------------------------
# Defaults / configuration
# ---------------------------------------------------------------------------
MODE="normal"              # fast | normal | deep
OUT_PATH=""                # explicit --out
TO_STDOUT=0
REDACT=0
DO_NETWORK=1
QUIET=0
ALLOW_SUDO_PROMPT=0
NO_SUDO=0
OS_CHECK=1
ONLY_SECTIONS=""
SKIP_SECTIONS=""

DEFAULT_TIMEOUT=45         # seconds per command
MAX_LINES=200              # lines kept per command
MAX_BYTES=400000           # bytes kept per command
LOG_WINDOW="2h"            # window for `log show`

USER_TIMEOUT=""
USER_MAX_LINES=""

ALL_SECTIONS="meta hardware os security mdm sso users network storage power processes software updates logs peripherals certs time tests"

# Runtime state
ABORTED=0
CMD_COUNT=0
CMD_FAILED=0
CMD_TIMEOUT=0
CMD_SKIPPED=0
START_EPOCH=0
RUN_OUT=""
RUN_RC=0
CUR_SECTION="meta"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
$SCRIPT_NAME v$VERSION — read-only macOS system audit collector

Collects a large, structured, read-only snapshot of this Mac into a single
Markdown report suitable for pasting into an AI assistant or a ticket.

USAGE
  bash $SCRIPT_NAME [options]
  sudo bash $SCRIPT_NAME [options]     # richer: privileged read-only data

OUTPUT
  -o, --out PATH        Write the report to PATH (file, or directory to
                        auto-name inside). Default: ~/Desktop, else ~,
                        else \$TMPDIR.
      --stdout          Write the report to stdout instead of a file.
  -q, --quiet           Suppress progress output on stderr.

SCOPE
      --fast            Fewer/shorter collections; skips slow log queries.
      --deep            Everything, longer log windows, extra benchmarks,
                        code-signature checks, powermetrics (needs root).
      --only  a,b,c     Run only these sections.
      --skip  a,b,c     Run everything except these sections.
      --list-sections   Print the section IDs and exit.
      --no-network      Do not make any outbound network request.

PRIVACY
      --redact          Mask serial numbers, UUIDs, MAC addresses and email
                        addresses / UPNs in the report. Off by default because
                        those values are usually needed for diagnosis.
                        (Long opaque tokens and private keys are ALWAYS
                        elided, regardless of this flag.)

PRIVILEGE
      --sudo            Prompt once for a sudo credential up front, then use
                        it for read-only privileged queries.
      --no-sudo         Never invoke sudo, even if a cached credential exists.

TUNING
      --timeout N       Per-command timeout in seconds (default $DEFAULT_TIMEOUT).
      --max-lines N     Max lines kept per command (default $MAX_LINES).

MISC
      --no-os-check     Do not abort on non-macOS (harness testing only).
  -V, --version         Print version and exit.
  -h, --help            This help.

This script never modifies the system. See the header comment for the full
read-only safety model.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -o|--out)        OUT_PATH="${2:-}"; shift 2 ;;
        --out=*)         OUT_PATH="${1#*=}"; shift ;;
        --stdout)        TO_STDOUT=1; shift ;;
        -q|--quiet)      QUIET=1; shift ;;
        --fast)          MODE="fast"; shift ;;
        --deep)          MODE="deep"; shift ;;
        --only)          ONLY_SECTIONS="${2:-}"; shift 2 ;;
        --only=*)        ONLY_SECTIONS="${1#*=}"; shift ;;
        --skip)          SKIP_SECTIONS="${2:-}"; shift 2 ;;
        --skip=*)        SKIP_SECTIONS="${1#*=}"; shift ;;
        --list-sections) printf '%s\n' $ALL_SECTIONS; exit 0 ;;
        --no-network)    DO_NETWORK=0; shift ;;
        --redact)        REDACT=1; shift ;;
        --sudo)          ALLOW_SUDO_PROMPT=1; shift ;;
        --no-sudo)       NO_SUDO=1; shift ;;
        --timeout)       USER_TIMEOUT="${2:-}"; shift 2 ;;
        --timeout=*)     USER_TIMEOUT="${1#*=}"; shift ;;
        --max-lines)     USER_MAX_LINES="${2:-}"; shift 2 ;;
        --max-lines=*)   USER_MAX_LINES="${1#*=}"; shift ;;
        --no-os-check)   OS_CHECK=0; shift ;;
        -V|--version)    printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"; exit 0 ;;
        -h|--help)       usage; exit 0 ;;
        *)
            printf 'error: unknown option: %s\n' "$1" >&2
            printf 'try: bash %s --help\n' "$SCRIPT_NAME" >&2
            exit 2
            ;;
    esac
done

case "$MODE" in
    fast)   DEFAULT_TIMEOUT=15; MAX_LINES=80;  LOG_WINDOW="15m" ;;
    normal) DEFAULT_TIMEOUT=45; MAX_LINES=200; LOG_WINDOW="2h"  ;;
    deep)   DEFAULT_TIMEOUT=90; MAX_LINES=600; LOG_WINDOW="12h" ;;
esac
[ -n "$USER_TIMEOUT" ]   && DEFAULT_TIMEOUT="$USER_TIMEOUT"
[ -n "$USER_MAX_LINES" ] && MAX_LINES="$USER_MAX_LINES"

case "$DEFAULT_TIMEOUT" in ''|*[!0-9]*) printf 'error: --timeout must be an integer\n' >&2; exit 2 ;; esac
case "$MAX_LINES"       in ''|*[!0-9]*) printf 'error: --max-lines must be an integer\n' >&2; exit 2 ;; esac
[ "$DEFAULT_TIMEOUT" -lt 5 ] && DEFAULT_TIMEOUT=5
[ "$MAX_LINES" -lt 1 ] && MAX_LINES=1

# ---------------------------------------------------------------------------
# Platform check
# ---------------------------------------------------------------------------
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
if [ "$OS_CHECK" = 1 ] && [ "$UNAME_S" != "Darwin" ]; then
    cat >&2 <<EOF
error: this script audits macOS and this system reports "$UNAME_S".
       Re-run on a Mac, or pass --no-os-check to exercise the harness anyway.
EOF
    exit 1
fi

# ---------------------------------------------------------------------------
# Working files
# ---------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/macos-audit.XXXXXX" 2>/dev/null)" || {
    printf 'error: could not create a temporary directory\n' >&2; exit 1; }
BODY="$WORKDIR/body.md"
HEADER="$WORKDIR/header.md"
FINDINGS_FILE="$WORKDIR/findings.tsv"
FACTS_FILE="$WORKDIR/facts.tsv"
RUN_OUT="$WORKDIR/last.out"
: >"$BODY"; : >"$FINDINGS_FILE"; : >"$FACTS_FILE"; : >"$RUN_OUT"

cleanup() {
    [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR" ] && rm -rf "$WORKDIR" 2>/dev/null
}
trap cleanup EXIT
on_interrupt() {
    ABORTED=1
    progress ""
    progress "!! interrupted — assembling a partial report from what was collected"
}
trap on_interrupt INT TERM

# ---------------------------------------------------------------------------
# Environment facts used throughout
# ---------------------------------------------------------------------------
IS_ROOT=0
[ "$(id -u 2>/dev/null || echo 1)" = "0" ] && IS_ROOT=1

CONSOLE_USER="$(stat -f "%Su" /dev/console 2>/dev/null | head -1)"
# Guard against a non-BSD `stat` (or a console owned by root) returning
# something that is not a usable account name.
case "$CONSOLE_USER" in
    ""|root|*[!A-Za-z0-9._-]*) CONSOLE_USER="" ;;
esac
if [ -z "$CONSOLE_USER" ] || ! id "$CONSOLE_USER" >/dev/null 2>&1; then
    CONSOLE_USER="${SUDO_USER:-${USER:-$(id -un 2>/dev/null)}}"
fi
[ -z "${CONSOLE_USER:-}" ] && CONSOLE_USER="root"
USER_HOME="$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -z "${USER_HOME:-}" ] && USER_HOME="${HOME:-/Users/$CONSOLE_USER}"
[ -d "$USER_HOME" ] || USER_HOME="${HOME:-/tmp}"

HOSTNAME_SHORT="$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || echo mac)"
HOSTNAME_SAFE="$(printf '%s' "$HOSTNAME_SHORT" | tr -c 'A-Za-z0-9._-' '-' | sed 's/-\{2,\}/-/g;s/^-//;s/-$//')"
[ -z "$HOSTNAME_SAFE" ] && HOSTNAME_SAFE="mac"
STAMP="$(date '+%Y%m%d-%H%M%S' 2>/dev/null || echo unknown)"

SUDO_AVAILABLE=0
init_sudo() {
    [ "$NO_SUDO" = 1 ] && return 0
    [ "$IS_ROOT" = 1 ] && { SUDO_AVAILABLE=1; return 0; }
    command -v sudo >/dev/null 2>&1 || return 0
    if [ "$ALLOW_SUDO_PROMPT" = 1 ]; then
        progress "== requesting a sudo credential (read-only queries only)"
        if sudo -v 2>/dev/null; then SUDO_AVAILABLE=1; fi
    fi
    if [ "$SUDO_AVAILABLE" = 0 ] && sudo -n true 2>/dev/null; then
        SUDO_AVAILABLE=1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
progress() {
    [ "$QUIET" = 1 ] && return 0
    printf '%s\n' "$*" >&2
}

o() { printf '%s\n' "$*" >>"$BODY"; }

section() {
    CUR_SECTION="$1"
    o ""
    o "---"
    o ""
    o "## $2"
    o ""
    o "<!-- section-id: $1 -->"
    progress "== $2"
}

sub() {
    o ""
    o "### $1"
    o ""
}

note() { o "> $*"; o ""; }

fact()    { printf '%s\t%s\n' "$1" "$2" >>"$FACTS_FILE"; }
getfact() { awk -F'\t' -v k="$1" '$1==k{v=$2} END{print v}' "$FACTS_FILE" 2>/dev/null; }

# finding SEVERITY "title" "detail"
finding() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$FINDINGS_FILE"; }

# ---------------------------------------------------------------------------
# Output scrubbing
#   scrub_always : applied unconditionally (secret-shaped material, fences)
#   scrub_redact : applied only with --redact
# ---------------------------------------------------------------------------
#
# NOTE ON PORTABILITY: macOS ships BSD sed. It does NOT support GNU's `\b`
# word boundary or the `I` (case-insensitive) substitute flag — using either
# makes sed abort and silently swallow the whole block. Everything below is
# written to BSD ERE only, and _selftest_scrub() verifies at startup that the
# filters actually pass data through; if they do not, they degrade to `cat`.
#
SCRUB_OK=1

scrub_always() {
    [ "$SCRUB_OK" = 1 ] || { cat; return 0; }
    LC_ALL=C sed -E \
        -e 's/```/'"'''"'/g' \
        -e '/-----BEGIN [A-Za-z ]*PRIVATE KEY-----/,/-----END [A-Za-z ]*PRIVATE KEY-----/d' \
        -e 's#[A-Za-z0-9+/=_-]{200,}#<LONG-OPAQUE-TOKEN-ELIDED>#g' \
        -e 's#([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Kk][Ee][Yy]|[Pp][Ss][Kk]|[Bb][Ee][Aa][Rr][Ee][Rr])([A-Za-z0-9_]*)[[:space:]]*[=:][[:space:]]*[^[:space:]]{4,}#\1\2=<ELIDED>#g' \
        2>/dev/null
}

scrub_redact() {
    if [ "$REDACT" != 1 ] || [ "$SCRUB_OK" != 1 ]; then cat; return 0; fi
    LC_ALL=C sed -E \
        -e 's/([Ss]erial[^:]{0,24}:[[:space:]]*)[A-Za-z0-9]{6,}/\1<REDACTED-SERIAL>/g' \
        -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<REDACTED-EMAIL>/g' \
        -e 's/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/<REDACTED-MAC>/g' \
        -e 's/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/<REDACTED-UUID>/g' \
        2>/dev/null
}

# Verify the filters do not eat their input on this platform's sed.
_selftest_scrub() {
    local probe out
    probe='probe token=abcdefgh user@example.com 00:11:22:33:44:55 A1B2C3D4-E5F6-7890-ABCD-EF1234567890'
    out="$(printf '%s\n' "$probe" | scrub_always)"
    [ -n "${out:-}" ] || SCRUB_OK=0
    if [ "$SCRUB_OK" = 1 ] && [ "$REDACT" = 1 ]; then
        out="$(printf '%s\n' "$probe" | scrub_redact)"
        [ -n "${out:-}" ] || SCRUB_OK=0
    fi
    [ "$SCRUB_OK" = 1 ] || progress "!! output filters unusable on this sed — continuing without them"
    return 0
}

# ---------------------------------------------------------------------------
# Bounded command execution
# ---------------------------------------------------------------------------
_kill_tree() {
    local pid="$1" sig="${2:-TERM}" kid
    for kid in $(pgrep -P "$pid" 2>/dev/null); do
        _kill_tree "$kid" "$sig"
    done
    kill -"$sig" "$pid" 2>/dev/null
    return 0
}

# _exec_timeout SECONDS OUTFILE -- argv...
# Runs argv in the background, kills the whole process tree on timeout.
# Returns the command's exit status, or 124 on timeout.
_exec_timeout() {
    local secs="$1" outfile="$2"; shift 2
    local pid ms limit_ms rc

    "$@" >"$outfile" 2>&1 &
    pid=$!

    ms=0
    limit_ms=$(( secs * 1000 ))
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$ms" -ge "$limit_ms" ]; then
            _kill_tree "$pid" TERM
            sleep 0.5
            _kill_tree "$pid" KILL
            wait "$pid" 2>/dev/null
            return 124
        fi
        # Poll finely for the first second (most queries return instantly),
        # then back off so a long collection does not burn CPU on polling.
        if [ "$ms" -lt 1000 ]; then
            sleep 0.05; ms=$(( ms + 50 ))
        else
            sleep 0.25; ms=$(( ms + 250 ))
        fi
    done
    wait "$pid" 2>/dev/null
    rc=$?
    return $rc
}

_emit_skip() {
    # _emit_skip "heading" "reason"
    # Clearing RUN_OUT matters: heuristics inspect the *previous* command's
    # output, and a skipped command must not leave a stale buffer behind.
    : >"$RUN_OUT"
    RUN_RC=127
    o "#### $1"
    o ""
    o "> _skipped: $2_"
    o ""
    CMD_SKIPPED=$(( CMD_SKIPPED + 1 ))
}

# _emit_output HEADING RC DURATION MAXLINES
_emit_output() {
    local heading="$1" rc="$2" dur="$3" maxl="$4"
    local total kept meta=""

    total="$(wc -l <"$RUN_OUT" 2>/dev/null | tr -d ' ')"
    [ -z "${total:-}" ] && total=0
    kept="$total"
    if [ "$total" -gt "$maxl" ]; then kept="$maxl"; fi

    o "#### $heading"
    o ""

    [ "$rc" != "0" ] && meta="exit=$rc"
    if [ "$rc" = "124" ]; then meta="TIMED OUT after ${dur}s"; fi
    [ "$dur" -ge 3 ] && meta="${meta:+$meta · }${dur}s"
    if [ "$total" -gt "$maxl" ]; then
        meta="${meta:+$meta · }truncated to first $kept of $total lines"
    fi
    [ -n "$meta" ] && { o "> _${meta}_"; o ""; }

    if [ ! -s "$RUN_OUT" ]; then
        o "_(no output)_"
        o ""
        return 0
    fi

    o '```text'
    head -c "$MAX_BYTES" "$RUN_OUT" 2>/dev/null \
        | sed -n "1,${maxl}p;${maxl}q" 2>/dev/null \
        | scrub_always \
        | scrub_redact >>"$BODY"
    # Output without a trailing newline would otherwise swallow the closing fence.
    [ -n "$(tail -c 1 "$BODY" 2>/dev/null)" ] && printf '\n' >>"$BODY"
    o '```'
    o ""
    return 0
}

# run [-t SECS] [-m LINES] [-r] "<shell command string>"
#   -r : command needs root (uses sudo -n when not already root)
# The command string is executed with /bin/bash -c, so pipes and redirection
# work. Exported variables (e.g. $PRED) are visible to it.
run() {
    local t="$DEFAULT_TIMEOUT" m="$MAX_LINES" need_root=0 heading=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -t) t="$2"; shift 2 ;;
            -m) m="$2"; shift 2 ;;
            -r) need_root=1; shift ;;
            -l) heading="$2"; shift 2 ;;
            --) shift; break ;;
            *)  break ;;
        esac
    done
    local cmd="${1:-}"
    [ -z "$cmd" ] && return 0

    [ -z "$heading" ] && heading="\`$cmd\`"

    if [ "$ABORTED" = 1 ]; then
        _emit_skip "$heading" "run interrupted before this command"
        return 0
    fi

    # Availability check on the leading binary.
    local first bin
    first="${cmd%% *}"
    case "$first" in
        '('*|'{'|for|while|if|':'|'echo'|'test') bin="" ;;
        *) bin="$first" ;;
    esac
    if [ -n "$bin" ]; then
        case "$bin" in
            */*) [ -x "$bin" ] || { _emit_skip "$heading" "\`$bin\` is not present on this system"; return 0; } ;;
            *)   command -v "$bin" >/dev/null 2>&1 || { _emit_skip "$heading" "\`$bin\` is not present on this system"; return 0; } ;;
        esac
    fi

    if [ "$need_root" = 1 ] && [ "$IS_ROOT" != 1 ]; then
        if [ "$SUDO_AVAILABLE" != 1 ]; then
            _emit_skip "$heading" "requires root; re-run with sudo (or pass --sudo) to collect this"
            return 0
        fi
    fi

    : >"$RUN_OUT"
    local t0 t1 dur rc
    t0="$(date +%s 2>/dev/null || echo 0)"
    if [ "$need_root" = 1 ] && [ "$IS_ROOT" != 1 ]; then
        _exec_timeout "$t" "$RUN_OUT" sudo -n /bin/bash -c "$cmd"
        rc=$?
    else
        _exec_timeout "$t" "$RUN_OUT" /bin/bash -c "$cmd"
        rc=$?
    fi
    t1="$(date +%s 2>/dev/null || echo 0)"
    dur=$(( t1 - t0 )); [ "$dur" -lt 0 ] && dur=0

    # A long run can outlive the cached sudo timestamp. Detect that once and
    # stop pretending privileged collection is still possible.
    if [ "$need_root" = 1 ] && [ "$IS_ROOT" != 1 ] && [ "$rc" != "0" ] \
       && grep -q "password is required" "$RUN_OUT" 2>/dev/null; then
        SUDO_AVAILABLE=0
        _emit_skip "$heading" "the cached sudo credential expired part-way through this run; re-run with \`sudo bash $SCRIPT_NAME\` for privileged data"
        return 0
    fi

    RUN_RC=$rc
    CMD_COUNT=$(( CMD_COUNT + 1 ))
    [ "$rc" != "0" ] && CMD_FAILED=$(( CMD_FAILED + 1 ))
    [ "$rc" = "124" ] && CMD_TIMEOUT=$(( CMD_TIMEOUT + 1 ))

    _emit_output "$heading" "$rc" "$dur" "$m"
    return 0
}

# run_fn "Heading" funcname [args...]  — same machinery for shell functions
run_fn() {
    local t="$DEFAULT_TIMEOUT" m="$MAX_LINES"
    while [ $# -gt 0 ]; do
        case "$1" in
            -t) t="$2"; shift 2 ;;
            -m) m="$2"; shift 2 ;;
            --) shift; break ;;
            *)  break ;;
        esac
    done
    local heading="$1"; shift

    if [ "$ABORTED" = 1 ]; then
        _emit_skip "$heading" "run interrupted before this collection"
        return 0
    fi

    : >"$RUN_OUT"
    local t0 t1 dur rc
    t0="$(date +%s 2>/dev/null || echo 0)"
    _exec_timeout "$t" "$RUN_OUT" "$@"
    rc=$?
    t1="$(date +%s 2>/dev/null || echo 0)"
    dur=$(( t1 - t0 )); [ "$dur" -lt 0 ] && dur=0

    RUN_RC=$rc
    CMD_COUNT=$(( CMD_COUNT + 1 ))
    [ "$rc" != "0" ] && CMD_FAILED=$(( CMD_FAILED + 1 ))
    [ "$rc" = "124" ] && CMD_TIMEOUT=$(( CMD_TIMEOUT + 1 ))

    _emit_output "$heading" "$rc" "$dur" "$m"
    return 0
}

# show_file [-r] PATH [maxlines] — dump a text file
show_file() {
    local need_root=0
    if [ "${1:-}" = "-r" ]; then need_root=1; shift; fi
    local p="${1:-}" m="${2:-$MAX_LINES}"
    [ -z "$p" ] && return 0
    export _AF="$p"
    if [ -r "$p" ]; then
        run -m "$m" -l "file \`$p\`" 'cat "$_AF"'
    elif [ "$need_root" = 1 ] && { [ "$IS_ROOT" = 1 ] || [ "$SUDO_AVAILABLE" = 1 ]; }; then
        run -r -m "$m" -l "file \`$p\`" 'cat "$_AF"'
    elif [ -e "$p" ]; then
        _emit_skip "file \`$p\`" "exists but is not readable as $(id -un 2>/dev/null)"
    else
        _emit_skip "file \`$p\`" "does not exist (or its parent directory is not readable)"
    fi
}

# show_plist [-r] PATH [maxlines] — dump a plist (binary or XML) via plutil
show_plist() {
    local need_root=0
    if [ "${1:-}" = "-r" ]; then need_root=1; shift; fi
    local p="${1:-}" m="${2:-$MAX_LINES}"
    [ -z "$p" ] && return 0
    export _AF="$p"
    if [ -r "$p" ]; then
        run -m "$m" -l "plist \`$p\`" 'plutil -p "$_AF"'
    elif [ "$need_root" = 1 ] && { [ "$IS_ROOT" = 1 ] || [ "$SUDO_AVAILABLE" = 1 ]; }; then
        run -r -m "$m" -l "plist \`$p\`" 'plutil -p "$_AF"'
    elif [ -e "$p" ]; then
        _emit_skip "plist \`$p\`" "exists but is not readable as $(id -un 2>/dev/null)"
    else
        _emit_skip "plist \`$p\`" "does not exist (or its parent directory is not readable)"
    fi
}

# ---------------------------------------------------------------------------
# Section selection
# ---------------------------------------------------------------------------
_in_list() {
    # _in_list needle "a,b,c"
    local needle="$1" list="$2" item
    local IFS=','
    for item in $list; do
        [ "$item" = "$needle" ] && return 0
    done
    return 1
}

want() {
    local s="$1"
    if [ -n "$ONLY_SECTIONS" ]; then
        _in_list "$s" "$ONLY_SECTIONS" || return 1
        return 0
    fi
    if [ -n "$SKIP_SECTIONS" ]; then
        _in_list "$s" "$SKIP_SECTIONS" && return 1
    fi
    return 0
}

deep() { [ "$MODE" = "deep" ]; }
fast() { [ "$MODE" = "fast" ]; }

# ===========================================================================
# Helper collectors (shell functions used with run_fn)
# ===========================================================================

_fn_local_users() {
    local u uid
    printf '%-24s %-8s %-8s %s\n' "SHORTNAME" "UID" "GID" "HOME"
    for u in $(dscl . -list /Users 2>/dev/null | grep -v '^_'); do
        uid="$(dscl . -read "/Users/$u" UniqueID 2>/dev/null | awk '{print $2}')"
        case "${uid:-}" in ''|*[!0-9]*) continue ;; esac
        [ "$uid" -lt 500 ] && continue
        printf '%-24s %-8s %-8s %s\n' \
            "$u" "$uid" \
            "$(dscl . -read "/Users/$u" PrimaryGroupID 2>/dev/null | awk '{print $2}')" \
            "$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    done
}

_fn_user_details() {
    local u uid
    for u in $(dscl . -list /Users 2>/dev/null | grep -v '^_'); do
        uid="$(dscl . -read "/Users/$u" UniqueID 2>/dev/null | awk '{print $2}')"
        case "${uid:-}" in ''|*[!0-9]*) continue ;; esac
        [ "$uid" -lt 500 ] && continue
        echo "=============================================================="
        echo "USER: $u"
        echo "--- RecordName / aliases:"
        dscl . -read "/Users/$u" RecordName 2>/dev/null
        echo "--- identity:"
        dscl . -read "/Users/$u" UniqueID PrimaryGroupID NFSHomeDirectory UserShell RealName 2>/dev/null
        echo "--- AuthenticationAuthority:"
        dscl . -read "/Users/$u" AuthenticationAuthority 2>/dev/null
        echo "--- AltSecurityIdentities (Platform SSO / Kerberos identity binding):"
        dscl . -read "/Users/$u" AltSecurityIdentities 2>/dev/null
        echo "--- OriginalNodeName / OriginalNFSHomeDirectory (mobile account markers):"
        dscl . -read "/Users/$u" OriginalNodeName OriginalNFSHomeDirectory 2>/dev/null
        echo "--- account policy (password policy attached to the record):"
        dscl . -readpl "/Users/$u" accountPolicyData 2>/dev/null | head -40
        echo "--- secure token:"
        sysadminctl -secureTokenStatus "$u" 2>&1
        echo "--- home directory:"
        ls -ld "$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')" 2>/dev/null
        echo
    done
}

_fn_admin_members() {
    echo "--- admin group members:"
    dscl . -read /Groups/admin GroupMembership 2>/dev/null
    echo
    echo "--- staff group:"
    dscl . -read /Groups/staff GroupMembership 2>/dev/null | head -5
    echo
    echo "--- _lpadmin (printer admins):"
    dscl . -read /Groups/_lpadmin GroupMembership 2>/dev/null
    echo
    echo "--- com.apple.access_ssh (remote login allowlist, if any):"
    dscl . -read /Groups/com.apple.access_ssh GroupMembership 2>/dev/null
}

_fn_network_services() {
    local svc line dev
    svc=""
    networksetup -listnetworkserviceorder 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            "("[0-9]*")"*)
                # "(1) Wi-Fi"  -> service name
                svc="${line#*) }"
                [ -z "$svc" ] && continue
                echo "=============================================================="
                echo "SERVICE: $svc"
                networksetup -getinfo "$svc" 2>&1
                echo "--- DNS servers:"
                networksetup -getdnsservers "$svc" 2>&1
                echo "--- search domains:"
                networksetup -getsearchdomains "$svc" 2>&1
                echo "--- proxies:"
                networksetup -getwebproxy "$svc" 2>&1
                networksetup -getsecurewebproxy "$svc" 2>&1
                networksetup -getsocksfirewallproxy "$svc" 2>&1
                networksetup -getautoproxyurl "$svc" 2>&1
                networksetup -getproxybypassdomains "$svc" 2>&1
                ;;
            "(Hardware Port:"*)
                # "(Hardware Port: Wi-Fi, Device: en0)"
                dev="${line##*Device: }"
                dev="${dev%)}"
                echo "--- device: $dev"
                [ -n "$dev" ] && networksetup -getMTU "$dev" 2>&1
                echo
                ;;
        esac
    done
}

_fn_wifi_info() {
    local dev
    dev="$(networksetup -listallhardwareports 2>/dev/null | awk '/Wi-Fi|AirPort/{getline; print $2; exit}')"
    if [ -z "${dev:-}" ]; then
        echo "no Wi-Fi hardware port found"
        return 0
    fi
    echo "Wi-Fi device: $dev"
    echo "--- current network:"
    networksetup -getairportnetwork "$dev" 2>&1
    echo "--- power:"
    networksetup -getairportpower "$dev" 2>&1
    echo "--- preferred networks (names only):"
    networksetup -listpreferredwirelessnetworks "$dev" 2>&1 | head -40
    echo "--- interface:"
    ifconfig "$dev" 2>&1
}

_fn_launch_items() {
    local d f label prog
    for d in /Library/LaunchDaemons /Library/LaunchAgents "$USER_HOME/Library/LaunchAgents" \
             /System/Library/LaunchDaemons.disabled; do
        [ -d "$d" ] || continue
        echo "=============================================================="
        echo "DIR: $d"
        for f in "$d"/*.plist; do
            [ -e "$f" ] || continue
            label="$(/usr/bin/defaults read "${f%.plist}" Label 2>/dev/null)"
            prog="$(/usr/bin/defaults read "${f%.plist}" Program 2>/dev/null)"
            [ -z "$prog" ] && prog="$(/usr/bin/defaults read "${f%.plist}" ProgramArguments 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-160)"
            printf '%s\n    label=%s\n    prog=%s\n' "$(basename "$f")" "${label:-?}" "${prog:-?}"
        done
        echo
    done
}

_fn_managed_prefs() {
    local f d
    for d in "/Library/Managed Preferences" "/Library/Managed Preferences/$CONSOLE_USER"; do
        [ -d "$d" ] || continue
        echo "=============================================================="
        echo "DIR: $d"
        ls -la "$d" 2>&1
        echo
        for f in "$d"/*.plist; do
            [ -e "$f" ] || continue
            echo "-------------------------------------------------------------"
            echo "MANAGED PREF: $f"
            plutil -p "$f" 2>&1 | head -120
            echo
        done
    done
}

_fn_applications() {
    local d app ver bid n=0
    printf '%-52s %-18s %s\n' "APP" "VERSION" "BUNDLE ID"
    for d in /Applications /Applications/Utilities "$USER_HOME/Applications" /System/Applications/Utilities; do
        [ -d "$d" ] || continue
        for app in "$d"/*.app; do
            [ -e "$app" ] || continue
            ver="$(/usr/bin/defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null | head -1)"
            bid="$(/usr/bin/defaults read "$app/Contents/Info" CFBundleIdentifier 2>/dev/null | head -1)"
            printf '%-52s %-18s %s\n' "$(basename "$app")" "${ver:-?}" "${bid:-?}"
            n=$(( n + 1 ))
            [ "$n" -ge 400 ] && { echo "... (stopped at 400 apps)"; return 0; }
        done
    done
}

_fn_app_signatures() {
    local d app
    for d in /Applications "$USER_HOME/Applications"; do
        [ -d "$d" ] || continue
        for app in "$d"/*.app; do
            [ -e "$app" ] || continue
            printf '=== %s\n' "$(basename "$app")"
            codesign -dv --verbose=2 "$app" 2>&1 | grep -E 'Authority|TeamIdentifier|Identifier=|flags=' | head -6
        done
    done
}

_fn_crash_reports() {
    local d
    for d in /Library/Logs/DiagnosticReports "$USER_HOME/Library/Logs/DiagnosticReports"; do
        [ -d "$d" ] || continue
        echo "=============================================================="
        echo "DIR: $d"
        ls -lt "$d" 2>/dev/null | head -40
        echo
    done
}

_fn_latest_panic() {
    local f
    f="$(ls -t /Library/Logs/DiagnosticReports/*.panic 2>/dev/null | head -1)"
    if [ -z "${f:-}" ]; then
        echo "no .panic reports found in /Library/Logs/DiagnosticReports"
        return 0
    fi
    echo "most recent panic report: $f"
    ls -l "$f" 2>/dev/null
    echo "--- first 80 lines:"
    head -80 "$f" 2>/dev/null
}

_fn_recent_crashes() {
    local f n=0
    for f in $(ls -t /Library/Logs/DiagnosticReports/*.ips "$USER_HOME"/Library/Logs/DiagnosticReports/*.ips 2>/dev/null | head -8); do
        echo "=============================================================="
        echo "CRASH: $f"
        head -30 "$f" 2>/dev/null
        echo
        n=$(( n + 1 ))
    done
    [ "$n" = 0 ] && echo "no .ips crash reports found"
    return 0
}

_fn_https_probe() {
    local url fmt
    fmt='  dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s http=%{http_code} ip=%{remote_ip}\n'
    for url in \
        "https://www.apple.com/" \
        "https://captive.apple.com/hotspot-detect.html" \
        "https://swscan.apple.com/content/catalogs/index.sucatalog" \
        "https://gs.apple.com/" \
        "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https://login.microsoftonline.com/common/oauth2/v2.0/authorize" \
        "https://login.microsoft.com/" \
        "https://device.login.microsoftonline.com/" \
        "https://enterpriseregistration.windows.net/" \
        "https://manage.microsoft.com/" \
        "https://graph.microsoft.com/" \
        "https://app-site-association.cdn-apple.com/" \
        "https://identity.apple.com/" \
        "https://mdmenrollment.apple.com/"
    do
        printf '%s\n' "$url"
        curl --silent --show-error --location --max-time 12 --connect-timeout 6 \
             --output /dev/null --write-out "$fmt" "$url" 2>&1
    done
}

_fn_tls_chain() {
    local host
    for host in \
        login.microsoftonline.com \
        device.login.microsoftonline.com \
        enterpriseregistration.windows.net \
        manage.microsoft.com \
        www.apple.com \
        gdmf.apple.com
    do
        echo "=============================================================="
        echo "HOST: $host"
        # Bound the TCP connect first: openssl s_client has no connect timeout
        # and a blackholed port would otherwise burn the whole budget.
        if command -v nc >/dev/null 2>&1; then
            if ! nc -z -G 3 -w 3 "$host" 443 >/dev/null 2>&1 \
               && ! nc -z -w 3 "$host" 443 >/dev/null 2>&1; then
                echo "TCP 443 not reachable within 3s — skipped"
                continue
            fi
        fi
        echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null \
            | openssl x509 -noout -issuer -subject -dates 2>&1
    done
    echo
    echo "NOTE: an issuer that is not a public CA (e.g. a firewall/appliance name)"
    echo "      indicates TLS interception, which commonly breaks MDM enrollment,"
    echo "      Platform SSO registration and softwareupdate."
}

_fn_dns_probe() {
    local h resolver
    for h in apple.com login.microsoftonline.com manage.microsoft.com \
             enterpriseregistration.windows.net gdmf.apple.com swscan.apple.com
    do
        echo "--- $h"
        if command -v dig >/dev/null 2>&1; then
            dig +time=3 +tries=1 +short "$h" 2>&1 | head -6
        elif command -v host >/dev/null 2>&1; then
            host -W 3 "$h" 2>&1 | head -6
        else
            dscacheutil -q host -a name "$h" 2>&1 | head -8
        fi
    done
    echo
    echo "--- system resolver view (dscacheutil, honours search domains/DNS proxies):"
    dscacheutil -q host -a name apple.com 2>&1 | head -10
}

_fn_ping_probe() {
    local gw
    gw="$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')"
    if [ -n "${gw:-}" ]; then
        echo "--- default gateway: $gw"
        ping -c 3 -t 5 "$gw" 2>&1 | tail -5
    else
        echo "--- no default gateway found in the routing table"
    fi
    echo "--- 1.1.1.1 (Cloudflare):"
    ping -c 3 -t 5 1.1.1.1 2>&1 | tail -5
    echo "--- 8.8.8.8 (Google):"
    ping -c 3 -t 5 8.8.8.8 2>&1 | tail -5
    echo "--- apple.com:"
    ping -c 3 -t 5 apple.com 2>&1 | tail -5
}

_fn_mdm_vendors() {
    echo "=============================================================="
    echo "Jamf Pro"
    if [ -x /usr/local/bin/jamf ]; then
        /usr/local/bin/jamf version 2>&1
        ls -la /Library/Preferences/com.jamfsoftware.jamf.plist 2>&1
        plutil -p /Library/Preferences/com.jamfsoftware.jamf.plist 2>&1 | head -40
    else
        echo "jamf binary not installed"
    fi

    echo
    echo "=============================================================="
    echo "Microsoft Intune / Company Portal"
    for p in "/Applications/Company Portal.app" \
             "/Library/Application Support/Microsoft/Intune" \
             "/Library/Intune" \
             "/Library/Logs/Microsoft/Intune"; do
        if [ -e "$p" ]; then
            echo "--- present: $p"
            ls -la "$p" 2>&1 | head -20
        else
            echo "--- absent:  $p"
        fi
    done
    if [ -e "/Applications/Company Portal.app/Contents/Info.plist" ]; then
        echo "--- Company Portal version:"
        /usr/bin/defaults read "/Applications/Company Portal.app/Contents/Info" CFBundleShortVersionString 2>&1
        /usr/bin/defaults read "/Applications/Company Portal.app/Contents/Info" CFBundleVersion 2>&1
    fi
    if [ -e "/Library/Intune/Microsoft Intune Agent.app/Contents/Info.plist" ]; then
        echo "--- Intune MDM Agent version:"
        /usr/bin/defaults read "/Library/Intune/Microsoft Intune Agent.app/Contents/Info" CFBundleShortVersionString 2>&1
    fi

    echo
    echo "=============================================================="
    echo "JumpCloud"
    for p in /opt/jc /opt/jc/jcagent.conf /Library/LaunchDaemons/com.jumpcloud.darwin-agent.plist \
             /Applications/JumpCloud.app; do
        if [ -e "$p" ]; then echo "--- present: $p"; ls -la "$p" 2>&1 | head -12; else echo "--- absent:  $p"; fi
    done

    echo
    echo "=============================================================="
    echo "Other management agents"
    for p in /usr/local/bin/kandji /Library/Kandji /Applications/Kandji\ Self\ Service.app \
             /usr/local/mosyle /Applications/Mosyle*.app \
             /Library/Addigy /Library/Application\ Support/Addigy \
             /Applications/Rippling*.app /Library/Application\ Support/Rippling \
             /Applications/Munki* /usr/local/munki \
             /Library/Application\ Support/Workspace\ ONE\ Intelligent\ Hub \
             /Applications/Workspace\ ONE\ Intelligent\ Hub.app; do
        [ -e "$p" ] && { echo "--- present: $p"; }
    done
    echo "(only present paths are listed above)"
}

_fn_sso_extensions() {
    # Only the three documented read-only forms of app-sso are used here:
    #   -l              list registered SSO extensions
    #   -i <bundle id>  print one extension's state
    #   platform -s     print Platform SSO device/user state
    # No other flag is guessed at, because app-sso also has verbs that trigger
    # or tear down registration.
    echo "--- app-sso extension list (app-sso -l):"
    app-sso -l 2>&1
    echo
    echo "--- Microsoft Company Portal SSO extension:"
    app-sso -i com.microsoft.CompanyPortalMac 2>&1 | head -60
    echo
    echo "--- Apple Kerberos SSO extension (if configured):"
    app-sso -i com.apple.AppSSOKerberos.KerberosExtension 2>&1 | head -40
    echo
    echo "--- Kerberos tickets for the console user (klist):"
    klist 2>&1 | head -30
}

_fn_disk_read_bench() {
    local f sz
    for f in /System/Library/dyld/dyld_shared_cache_arm64e \
             /System/Library/dyld/dyld_shared_cache_x86_64h \
             /System/Library/dyld/dyld_shared_cache_x86_64 \
             /System/Volumes/Preboot/*/boot/*/System/Library/Caches/com.apple.kernelcaches/kernelcache; do
        [ -f "$f" ] || continue
        sz="$(stat -f %z "$f" 2>/dev/null || echo 0)"
        [ "${sz:-0}" -lt 67108864 ] && continue
        echo "reading 256 MiB from: $f"
        echo "(read-only; nothing is written anywhere)"
        dd if="$f" of=/dev/null bs=1m count=256 2>&1
        return 0
    done
    echo "no suitably large system file found for a read benchmark; skipped"
}

_fn_cpu_bench() {
    echo "--- openssl digest throughput, 1 second per algorithm (CPU only):"
    openssl speed -elapsed -seconds 1 sha256 2>&1 | tail -8
}

_fn_time_machine() {
    echo "--- destinations:"
    tmutil destinationinfo 2>&1
    echo
    echo "--- latest backup:"
    tmutil latestbackup 2>&1
    echo
    echo "--- current status:"
    tmutil status 2>&1 | head -30
    echo
    echo "--- local snapshots on /:"
    tmutil listlocalsnapshots / 2>&1 | head -30
    echo
    echo "--- local snapshots on the data volume:"
    tmutil listlocalsnapshots /System/Volumes/Data 2>&1 | head -30
}

_fn_keychain_certs() {
    echo "--- keychain search list:"
    security list-keychains 2>&1
    echo
    echo "--- default keychain:"
    security default-keychain 2>&1
    echo
    echo "--- System keychain certificate labels (names only, no key material):"
    security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null \
        | grep -E '"(labl|subj)"' | head -80
    echo
    echo "--- login keychain certificate labels:"
    security find-certificate -a 2>/dev/null | grep '"labl"' | head -60
    echo
    echo "--- identities with usable private keys in the System keychain:"
    security find-identity -v /Library/Keychains/System.keychain 2>&1 | head -40
    echo
    echo "--- identities visible to the current user:"
    security find-identity -v 2>&1 | head -40
}

_fn_expiring_certs() {
    local pem="" line tmp state
    tmp="$WORKDIR/cert.pem"
    echo "STATE      | notAfter                      | subject"
    echo "-----------|-------------------------------|------------------------------"
    echo "(EXPIRED / <90d = the certificate is gone or goes within 90 days;"
    echo " an expiring MDM, SCEP or device-identity certificate breaks enrollment)"
    echo
    security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null \
    | while IFS= read -r line; do
        pem="$pem$line
"
        case "$line" in
            "-----END CERTIFICATE-----")
                printf '%s' "$pem" >"$tmp"
                pem=""
                if ! openssl x509 -in "$tmp" -noout -checkend 0 >/dev/null 2>&1; then
                    state="EXPIRED   "
                elif ! openssl x509 -in "$tmp" -noout -checkend 7776000 >/dev/null 2>&1; then
                    state="<90d      "
                else
                    state="ok        "
                fi
                printf '%s | %-29s | %s\n' \
                    "$state" \
                    "$(openssl x509 -in "$tmp" -noout -enddate 2>/dev/null | sed 's/notAfter=//')" \
                    "$(openssl x509 -in "$tmp" -noout -subject 2>/dev/null | sed 's/^subject= *//' | cut -c1-110)"
                ;;
        esac
    done | sort | head -100
    rm -f "$tmp" 2>/dev/null
    return 0
}

# ===========================================================================
# Sections
# ===========================================================================

mod_meta() {
    section meta "Audit metadata & host identity"
    note "Generated by \`$SCRIPT_NAME\` v$VERSION — a read-only collector. \
No system state was modified. Commands that require root are marked as skipped \
when the script is not running with sufficient privileges."

    sub "Run context"
    o '```text'
    {
        printf 'script version   : %s\n' "$VERSION"
        printf 'mode             : %s\n' "$MODE"
        printf 'started          : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)"
        printf 'started (UTC)    : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
        printf 'invoked as       : %s (uid %s)\n' "$(id -un 2>/dev/null)" "$(id -u 2>/dev/null)"
        printf 'console user     : %s\n' "$CONSOLE_USER"
        printf 'console home     : %s\n' "$USER_HOME"
        printf 'running as root  : %s\n' "$([ "$IS_ROOT" = 1 ] && echo yes || echo no)"
        printf 'sudo available   : %s\n' "$([ "$SUDO_AVAILABLE" = 1 ] && echo yes || echo no)"
        printf 'network probes   : %s\n' "$([ "$DO_NETWORK" = 1 ] && echo enabled || echo disabled)"
        printf 'redaction        : %s\n' "$([ "$REDACT" = 1 ] && echo on || echo off)"
        printf 'per-cmd timeout  : %ss\n' "$DEFAULT_TIMEOUT"
        printf 'per-cmd maxlines : %s\n' "$MAX_LINES"
        printf 'log window       : %s\n' "$LOG_WINDOW"
        printf 'shell            : %s\n' "${BASH_VERSION:-unknown}"
    } | scrub_always | scrub_redact >>"$BODY"
    o '```'
    o ""

    sub "Host names"
    run "scutil --get ComputerName"
    run "scutil --get LocalHostName"
    run "scutil --get HostName"
    run "hostname"
    run "id"
    run "who"
    run -m 30 "last -20"
}

mod_hardware() {
    section hardware "Hardware"

    sub "Model, CPU, memory"
    run -t 90 "system_profiler SPHardwareDataType"
    local model
    model="$(sysctl -n hw.model 2>/dev/null)"
    fact hw.model "${model:-unknown}"

    run "sysctl -n machdep.cpu.brand_string"
    run "sysctl hw.model hw.machine hw.memsize hw.ncpu hw.physicalcpu hw.logicalcpu hw.cpufrequency_max hw.pagesize"
    run "sysctl -n hw.optional.arm64"
    run "arch"
    run "uname -m"

    sub "Platform / firmware identity"
    run -m 60 "ioreg -d2 -c IOPlatformExpertDevice"
    run -m 120 "nvram -p"
    run -r "nvram -x -p"
    run -r "system_profiler SPiBridgeDataType"

    sub "Apple silicon boot policy (Secure Boot level)"
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
        run -r "bputil -d"
    else
        _emit_skip "\`bputil -d\`" "Intel Mac (bputil is Apple silicon only)"
        run -r "firmwarepasswd -check"
    fi

    sub "Extended hardware inventory"
    run -t 120 -m 300 "system_profiler SPMemoryDataType SPPCIDataType SPNVMeDataType SPSerialATADataType"
}

mod_os() {
    section os "Operating system, boot state & uptime"

    sub "Version"
    run "sw_vers"
    local osver build
    osver="$(sw_vers -productVersion 2>/dev/null)"
    build="$(sw_vers -buildVersion 2>/dev/null)"
    fact os.version "${osver:-unknown}"
    fact os.build "${build:-unknown}"

    run "uname -a"
    run "sysctl kern.osproductversion kern.osversion kern.osrelease kern.osrevision kern.version"
    run -t 90 "system_profiler SPSoftwareDataType"

    sub "Uptime & boot"
    run "uptime"
    run "sysctl -n kern.boottime"
    local boot_epoch now_epoch up_days
    boot_epoch="$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')"
    now_epoch="$(date +%s 2>/dev/null || echo 0)"
    if [ -n "${boot_epoch:-}" ] && [ "$boot_epoch" -gt 0 ] 2>/dev/null; then
        up_days=$(( (now_epoch - boot_epoch) / 86400 ))
        fact uptime.days "$up_days"
        if [ "$up_days" -ge 30 ]; then
            finding WARN "Uptime is ${up_days} days" \
                "Long uptime frequently correlates with stale daemon state (MDM check-in, SSO agents, DNS caches). A restart is a cheap first remediation."
        fi
    fi
    run -m 40 "last reboot"
    run -m 40 "last shutdown"

    sub "Boot volume & Rosetta"
    run "bless --info / --plist"
    run "csrutil authenticated-root status"
    if [ -d /Library/Apple/usr/share/rosetta ] || [ -d /Library/Apple/usr/libexec/oah ]; then
        o "Rosetta 2 appears to be **installed** (found /Library/Apple/usr/share/rosetta or .../libexec/oah)."
    else
        o "Rosetta 2 does not appear to be installed."
    fi
    o ""
    run "pkgutil --pkg-info com.apple.pkg.RosettaUpdateAuto"

    sub "Locale & environment"
    run "locale"
    run "defaults read -g AppleLanguages"
    run "defaults read -g AppleLocale"
    run -m 60 -l "sanitised environment of this shell" \
        'env | sed -E "s/^([A-Za-z_][A-Za-z0-9_]*(KEY|key|TOKEN|token|SECRET|secret|PASS|pass|CRED|cred|AUTH|auth|SESSION|session)[A-Za-z0-9_]*)=.*/\1=<ELIDED>/" | sort'
}

mod_security() {
    section security "Security posture"

    sub "System Integrity Protection"
    run "csrutil status"
    case "$(cat "$RUN_OUT" 2>/dev/null)" in
        *disabled*)
            fact sip enabled=no
            finding CRIT "System Integrity Protection (SIP) is disabled" \
                "csrutil reports SIP disabled. This is unusual on a managed Mac and weakens most other protections."
            ;;
        *enabled*) fact sip enabled=yes ;;
    esac

    sub "FileVault"
    run "fdesetup status"
    case "$(cat "$RUN_OUT" 2>/dev/null)" in
        *"FileVault is Off"*)
            fact filevault off
            finding WARN "FileVault is OFF" "The startup disk is not encrypted."
            ;;
        *"FileVault is On"*) fact filevault on ;;
    esac
    run -r "fdesetup list"
    run -r "fdesetup haspersonalrecoverykey"
    run -r "fdesetup hasinstitutionalrecoverykey"
    run -m 60 -l "\`diskutil apfs list\` (FileVault / encryption state per volume)" \
        'diskutil apfs list | grep -iE "FileVault|Encrypt|Volume Name|APFS Volume Disk|Unlocked|Locked"'

    sub "Secure boot, Gatekeeper & code signing policy"
    run "spctl --status"
    case "$(cat "$RUN_OUT" 2>/dev/null)" in
        *disabled*) finding WARN "Gatekeeper assessments are disabled" "spctl --status reports assessments disabled." ;;
    esac
    run "spctl developer-mode --status"
    run "defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist"

    sub "Malware protection data versions (XProtect / Gatekeeper / TCC config)"
    run -l "XProtect bundle version" \
        'defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString'
    run -l "XProtect Remediator version" \
        'defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info CFBundleShortVersionString'
    run -l "MRT (legacy) version" \
        'defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info CFBundleShortVersionString'
    run -l "Gatekeeper config data version" \
        'defaults read /private/var/db/gkopaque.bundle/Contents/Info CFBundleShortVersionString'
    run -m 40 -l "security config data install history" \
        'system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A3 -iE "XProtect|Gatekeeper|MRT|Config Data" | tail -60'

    sub "Application firewall (read-only getters)"
    run "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    case "$(cat "$RUN_OUT" 2>/dev/null)" in
        *disabled*) finding INFO "Application firewall is disabled" "socketfilterfw --getglobalstate reports the firewall off." ;;
    esac
    run "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
    run "/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall"
    run "/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned"
    run -m 60 "/usr/libexec/ApplicationFirewall/socketfilterfw --listapps"
    run -r -m 40 "pfctl -s info"
    run -r -m 60 "pfctl -s rules"

    sub "Kernel & system extensions"
    run -m 100 "kmutil showloaded --no-kernel-component"
    run -m 100 "systemextensionsctl list"
    run -m 60 -l "third-party kexts on disk" 'ls -la /Library/Extensions 2>&1'
    if [ -s "$RUN_OUT" ]; then
        if grep -qE '\.kext' "$RUN_OUT" 2>/dev/null; then
            finding INFO "Third-party kernel extensions are present in /Library/Extensions" \
                "Legacy kexts are a common cause of boot, sleep and networking faults on modern macOS."
        fi
    fi

    sub "Privacy (TCC) grants"
    note "Reading the TCC databases requires Full Disk Access. A failure here is expected and is itself informative."
    export _TCC_USER="$USER_HOME/Library/Application Support/com.apple.TCC/TCC.db"
    run -m 120 -l "user TCC grants" \
        'sqlite3 "$_TCC_USER" "select service, client, client_type, auth_value from access order by service" 2>&1'
    run -r -m 120 -l "system TCC grants" \
        'sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "select service, client, client_type, auth_value from access order by service" 2>&1'

    sub "Secure token, bootstrap token & volume ownership"
    run -r "profiles status -type bootstraptoken"
    run -m 60 -l "volume ownership / cryptousers for the data volume" \
        'diskutil apfs listusers / 2>&1'

    sub "Login window & screen lock policy"
    run -m 80 "defaults read /Library/Preferences/com.apple.loginwindow"
    export _LW="$USER_HOME/Library/Preferences/com.apple.screensaver.plist"
    run -l "user screensaver prefs" 'plutil -p "$_LW" 2>&1'
    run -l "managed screen-lock policy" \
        'plutil -p "/Library/Managed Preferences/com.apple.screensaver.plist" 2>&1'

    sub "Remote access services"
    run -r "systemsetup -getremotelogin"
    run "launchctl print-disabled system | grep -i -E 'ssh|screensharing|ard' "
    run -m 30 -l "SSH daemon config highlights" \
        'grep -vE "^[[:space:]]*(#|$)" /etc/ssh/sshd_config 2>/dev/null'
}

mod_mdm() {
    section mdm "Device management (MDM), enrollment & configuration profiles"
    note "This is usually the highest-value section for managed-Mac issues. \
Several commands here require root; run the script with \`sudo\` for full detail."

    sub "Enrollment state"
    run "profiles status -type enrollment"
    local enroll
    enroll="$(cat "$RUN_OUT" 2>/dev/null)"
    fact mdm.enrollment "$(printf '%s' "$enroll" | tr '\n' ';')"
    case "$enroll" in
        *"MDM enrollment: No"*)
            finding WARN "Device is not MDM-enrolled" \
                "\`profiles status -type enrollment\` reports no MDM enrollment. Any MDM-delivered payload (including Platform SSO) cannot apply."
            ;;
    esac
    case "$enroll" in
        *"Enrolled via DEP: No"*)
            finding INFO "Device is not enrolled via Automated Device Enrollment (DEP)" \
                "User-approved/manual enrollment limits which payloads can be applied without user consent."
            ;;
    esac
    run -r -m 120 "profiles show -type enrollment"

    sub "Installed configuration profiles"
    run -r -m 400 "profiles list -all"
    run -m 200 "profiles list"
    run -r -m 500 "profiles show"
    run -r -t 120 -m 600 "system_profiler SPConfigurationProfileDataType"

    sub "Profile installation records & MDM client state"
    run -m 60 -l "ConfigurationProfiles store" 'ls -la /var/db/ConfigurationProfiles/ 2>&1'
    run -m 60 -l "ConfigurationProfiles settings markers" 'ls -la /var/db/ConfigurationProfiles/Settings/ 2>&1'
    run -r -m 200 "/usr/libexec/mdmclient QuerySecurityInfo"
    run -r -m 120 -l "managed client preferences" 'plutil -p /Library/Preferences/com.apple.ManagedClient.plist 2>&1'

    sub "Managed (MDM-delivered) preference domains"
    run_fn -t 90 -m 700 "contents of /Library/Managed Preferences" _fn_managed_prefs

    sub "Management vendor agents"
    run_fn -t 90 -m 300 "Jamf / Intune / JumpCloud / other agent footprint" _fn_mdm_vendors

    sub "MDM push & check-in health"
    export PRED='subsystem == "com.apple.ManagedClient" OR process == "mdmclient" OR process == "profiles"'
    if fast; then
        _emit_skip "MDM unified-log excerpt" "--fast mode"
    else
        run -t 150 -m 300 -l "MDM unified log (last $LOG_WINDOW)" \
            'log show --last '"$LOG_WINDOW"' --style compact --predicate "$PRED" 2>&1 | tail -300'
    fi
    run -m 40 -l "APNs push connection state" 'scutil --nc list 2>&1; echo; netstat -an 2>/dev/null | grep -E "5223|443" | head -20'
}

mod_sso() {
    section sso "Platform SSO, directory services & identity binding"
    note "Covers Apple Platform SSO (Entra ID / Okta / Kerberos), Open Directory records, \
Active Directory binding, and the identity attributes those features read and write."

    sub "Platform SSO state"
    run -m 200 "app-sso platform -s"
    local psso
    psso="$(cat "$RUN_OUT" 2>/dev/null)"
    if [ -n "$psso" ]; then
        case "$psso" in
            *registrationCompleted*)
                case "$psso" in
                    *"registrationCompleted: false"*|*"registrationCompleted = 0"*)
                        finding WARN "Platform SSO user registration has NOT completed" \
                            "\`app-sso platform -s\` reports registrationCompleted: false. Device registration can be healthy while the per-user handshake (and password sync) is still pending."
                        ;;
                esac
                ;;
        esac
        case "$psso" in
            *"temporaryAccountCredentials"*)
                finding INFO "Platform SSO has staged temporary account credentials" \
                    "This is the interstitial state of a pending user registration, not a completed binding."
                ;;
        esac
        case "$psso" in
            *"User Configuration: (null)"*|*"User Configuration:  (null)"*)
                finding WARN "Platform SSO has no per-user login configuration" \
                    "\`User Configuration: (null)\` means no PSSO user configuration has been written for the console user yet."
                ;;
        esac
    fi

    run_fn -t 60 -m 200 "SSO extensions, Kerberos tickets and extension detail" _fn_sso_extensions

    sub "Extensible SSO configuration (MDM payload as applied)"
    run -m 200 -l "managed com.apple.extensiblesso" 'plutil -p "/Library/Managed Preferences/com.apple.extensiblesso.plist" 2>&1'
    run -m 200 -l "managed com.apple.extensiblesso (user scope)" 'plutil -p "/Library/Managed Preferences/'"$CONSOLE_USER"'/com.apple.extensiblesso.plist" 2>&1'
    run -r -m 200 -l "extensiblesso payload inside installed profiles" \
        'profiles show -all 2>/dev/null | grep -A 40 -i "extensiblesso"'
    run -m 60 -l "AppSSO daemon/agent processes" 'ps auxww | grep -iE "AppSSO|SSOExtension|CompanyPortal" | grep -v grep'

    sub "Open Directory records for local accounts"
    run_fn -t 90 -m 500 "per-user directory records (RecordName, AltSecurityIdentities, AuthenticationAuthority, secure token)" _fn_user_details

    sub "Directory search policy & node health"
    run "dscl /Search -read . CSPSearchPath"
    run "dscl localhost -list ."
    run -m 60 "odutil show nodenames"
    run -r -m 80 "odutil show all"
    run "dsconfigad -show"
    run -l "console user via dscacheutil" 'dscacheutil -q user -a name "'"$CONSOLE_USER"'"'
    run -l "id of the console user" 'id "'"$CONSOLE_USER"'"'

    sub "Platform SSO / AppSSO unified log"
    if fast; then
        _emit_skip "AppSSO unified-log excerpt" "--fast mode"
    else
        export PRED='subsystem CONTAINS[c] "AppSSO" OR process CONTAINS[c] "AppSSO" OR subsystem CONTAINS[c] "PlatformSSO" OR process CONTAINS[c] "CompanyPortal"'
        run -t 180 -m 400 -l "AppSSO / Platform SSO unified log (last $LOG_WINDOW)" \
            'log show --last '"$LOG_WINDOW"' --style compact --predicate "$PRED" 2>&1 | tail -400'
        export PRED='subsystem CONTAINS[c] "opendirectory" OR process == "opendirectoryd"'
        run -t 150 -m 200 -l "opendirectoryd unified log (last $LOG_WINDOW)" \
            'log show --last '"$LOG_WINDOW"' --style compact --predicate "$PRED" 2>&1 | tail -200'
    fi
}

mod_users() {
    section users "Users, groups & startup items"

    sub "Local user accounts"
    run_fn -m 120 "local accounts with UID >= 500" _fn_local_users
    run_fn -m 60 "group membership (admin, staff, lpadmin, ssh)" _fn_admin_members
    run -m 200 -l "all directory user records (including system accounts)" 'dscl . -list /Users'
    run "stat -f 'console user: %Su' /dev/console"

    sub "Login / logout history"
    run -m 60 "last -40"
    run -m 40 -l "failed login attempts in the log" \
        'log show --last 24h --style compact --predicate '"'"'eventMessage CONTAINS[c] "authentication failed" OR eventMessage CONTAINS[c] "Failed to authenticate"'"'"' 2>&1 | tail -40'

    sub "Login items, agents & daemons"
    run -r -m 300 "sfltool dumpbtm"
    run_fn -t 90 -m 400 "LaunchDaemons / LaunchAgents on disk" _fn_launch_items
    run -m 200 "launchctl list"
    run -r -m 200 -l "system launchd services" 'launchctl list'
    run -m 100 "launchctl print-disabled system"
    export _CUID="$(id -u "$CONSOLE_USER" 2>/dev/null || id -u)"
    run -m 100 -l "console user's disabled launchd services" 'launchctl print-disabled "user/$_CUID"'
    run -m 200 -l "console user's launchd domain (summary)" \
        'launchctl print "user/$_CUID" 2>&1 | head -200'

    sub "Per-user preference highlights"
    export _UH="$USER_HOME"
    run -m 60 -l "user's global preferences" 'plutil -p "$_UH/Library/Preferences/.GlobalPreferences.plist" 2>&1'
    run -m 40 -l "user's Dock/Finder autostart hints" 'ls -la "$_UH/Library/LaunchAgents" 2>&1'
}

mod_network() {
    section network "Network configuration & reachability"

    sub "Interfaces & addressing"
    run -m 200 "ifconfig -a"
    run -m 60 "networksetup -listallhardwareports"
    run -m 40 "networksetup -listnetworkserviceorder"
    run -m 40 "networksetup -listallnetworkservices"
    run -m 60 "scutil --nwi"
    run -m 60 -l "primary interface & router (SystemConfiguration)" \
        'echo "show State:/Network/Global/IPv4" | scutil'
    run -m 60 "netstat -rn"
    run -m 40 "arp -a -n"

    sub "Per-service configuration (addresses, DNS, proxies)"
    run_fn -t 120 -m 400 "networksetup details for every network service" _fn_network_services

    sub "DNS resolution policy"
    run -m 120 "scutil --dns"
    show_file /etc/hosts 80
    show_file /etc/resolv.conf 40
    run -m 40 -l "per-domain resolvers in /etc/resolver" \
        'ls -la /etc/resolver 2>/dev/null && cat /etc/resolver/* 2>/dev/null'
    run -m 40 -l "mDNSResponder / DNS proxy processes" \
        'ps auxww | grep -iE "mDNSResponder|dnscrypt|stubby|unbound|dnsmasq|Umbrella|Cloudflare WARP" | grep -v grep'

    sub "Proxies & VPN"
    run -m 60 "scutil --proxy"
    run -m 40 "scutil --nc list"
    run -m 60 -l "proxy-related environment variables" 'env | grep -iE "proxy|no_proxy"'
    run -m 40 -l "PAC / auto-proxy discovery state" 'echo "show State:/Network/Global/Proxies" | scutil'

    sub "Wi-Fi"
    run_fn -t 60 -m 120 "Wi-Fi interface, current SSID and preferred networks" _fn_wifi_info
    run -t 90 -m 200 "system_profiler SPAirPortDataType"
    run -r -t 60 -m 200 -l "\`wdutil info\` (detailed Wi-Fi state; contains SSID/BSSID)" 'wdutil info'

    sub "DHCP lease"
    run -m 60 -l "DHCP packet on the primary interface" \
        'ipconfig getpacket "$(route -n get default 2>/dev/null | awk "/interface:/{print \$2}")" 2>&1'

    sub "Listening sockets & active connections"
    run -m 120 -l "listening TCP/UDP sockets" 'netstat -an | grep -E "LISTEN|udp" | head -120'
    run -r -m 150 -l "processes bound to network sockets" 'lsof -nP -i | head -150'
    run -m 60 -l "socket statistics" 'netstat -s | head -60'

    sub "802.1X / network profiles"
    run -m 60 -l "802.1X profiles" 'ls -la /Library/Preferences/SystemConfiguration/com.apple.network.eapolclient* 2>&1'
    run -m 120 -l "SystemConfiguration preferences" 'plutil -p /Library/Preferences/SystemConfiguration/preferences.plist 2>&1'

    if [ "$DO_NETWORK" = 1 ]; then
        sub "Reachability probes (outbound)"
        note "These probes contact Apple, Cloudflare, Google DNS and Microsoft identity/management endpoints only. Disable with \`--no-network\`."
        run_fn -t 90 -m 120 "ICMP reachability" _fn_ping_probe
        run_fn -t 90 -m 120 "DNS resolution of key endpoints" _fn_dns_probe
        run_fn -t 180 -m 150 "HTTPS timing to Apple & Microsoft endpoints" _fn_https_probe
        run_fn -t 120 -m 120 "TLS certificate chain issuers (detects TLS interception)" _fn_tls_chain
        if grep -qiE 'issuer=.*(fortinet|fortigate|palo ?alto|zscaler|netskope|bluecoat|broadcom|sophos|cisco umbrella|umbrella|mcafee|websense|forcepoint|checkpoint|sonicwall|watchguard|barracuda|kaspersky|eset|proxy|firewall)' "$RUN_OUT" 2>/dev/null; then
            finding CRIT "TLS interception detected on at least one endpoint" \
                "The certificate issuer for one or more Apple/Microsoft endpoints is not a public CA. TLS inspection of these hosts breaks MDM enrollment, Platform SSO registration and softwareupdate. Exclude them from inspection."
        fi
        run -m 30 -l "captive portal check" \
            'curl -sS --max-time 10 http://captive.apple.com/hotspot-detect.html'
        case "$(cat "$RUN_OUT" 2>/dev/null)" in
            *Success*) : ;;
            *) finding WARN "Captive-portal check did not return Apple's expected response" \
                   "http://captive.apple.com/hotspot-detect.html did not return the 'Success' page: the network may require portal sign-in or is filtering HTTP." ;;
        esac
    else
        sub "Reachability probes (outbound)"
        note "Skipped: \`--no-network\` was passed."
    fi
}

mod_storage() {
    section storage "Storage, volumes & backups"

    sub "Free space"
    run -m 60 "df -h"
    run -m 60 "df -i"
    local avail_kb total_kb pct
    avail_kb="$(df -k / 2>/dev/null | awk 'NR==2{print $4}')"
    total_kb="$(df -k / 2>/dev/null | awk 'NR==2{print $2}')"
    if [ -n "${avail_kb:-}" ] && [ -n "${total_kb:-}" ] && [ "${total_kb:-0}" -gt 0 ] 2>/dev/null; then
        pct=$(( avail_kb * 100 / total_kb ))
        fact disk.free_pct "$pct"
        fact disk.free_gb "$(( avail_kb / 1048576 ))"
        if [ "$pct" -lt 10 ] || [ "$(( avail_kb / 1048576 ))" -lt 15 ]; then
            finding CRIT "Low free space on the boot volume" \
                "$(( avail_kb / 1048576 )) GiB free (${pct}%). Below ~15 GiB macOS updates fail, snapshots cannot be taken, and apps behave erratically."
        elif [ "$pct" -lt 20 ]; then
            finding WARN "Free space on the boot volume is getting low" \
                "$(( avail_kb / 1048576 )) GiB free (${pct}%)."
        fi
    fi

    sub "Volumes & APFS layout"
    run -m 200 "diskutil list"
    run -m 200 "diskutil apfs list"
    run -m 80 "diskutil info /"
    run -m 80 -l "data volume info" 'diskutil info /System/Volumes/Data'
    run -m 80 "mount"

    sub "Disk health"
    run -m 60 -l "SMART status per physical disk" \
        'diskutil info -all 2>/dev/null | grep -E "Device Identifier|SMART Status|Solid State|Media Name"'
    if grep -qiE 'SMART Status:[[:space:]]*(Failing|Failed)' "$RUN_OUT" 2>/dev/null; then
        finding CRIT "A disk reports a failing SMART status" \
            "Replace the drive before spending time on any other diagnosis — a failing disk explains almost any symptom."
    fi
    run -t 90 -m 120 "system_profiler SPStorageDataType"

    sub "Time Machine & snapshots"
    run_fn -t 90 -m 150 "Time Machine destinations, latest backup, snapshots" _fn_time_machine

    sub "Spotlight indexing"
    run -m 60 "mdutil -a -s"

    sub "Large directories in the console user's home (top level only)"
    export _UH="$USER_HOME"
    run -t 60 -m 40 -l "top-level home directory sizes" 'ls -la "$_UH" 2>&1 | head -40'
}

mod_power() {
    section power "Power, battery & thermals"

    sub "Power settings"
    run -m 80 "pmset -g"
    run -m 80 "pmset -g custom"
    run -m 40 "pmset -g ps"
    run -m 40 "pmset -g batt"
    run -m 60 "pmset -g assertions"
    run -m 30 "pmset -g sched"
    run -m 30 "pmset -g therm"

    sub "Battery health"
    run -t 90 -m 120 "system_profiler SPPowerDataType"
    local cond cycles
    cond="$(printf '%s' "$(cat "$RUN_OUT" 2>/dev/null)" | awk -F': *' '/Condition/{print $2; exit}')"
    cycles="$(printf '%s' "$(cat "$RUN_OUT" 2>/dev/null)" | awk -F': *' '/Cycle Count/{print $2; exit}')"
    [ -n "${cond:-}" ] && fact battery.condition "$cond"
    [ -n "${cycles:-}" ] && fact battery.cycles "$cycles"
    case "${cond:-}" in
        ""|Normal) : ;;
        *) finding WARN "Battery condition is reported as \"$cond\"" "Anything other than Normal (Replace Soon/Replace Now/Service Battery) causes throttling and unexpected shutdowns." ;;
    esac
    run -m 60 -l "AppleSmartBattery IORegistry entry" \
        'ioreg -rn AppleSmartBattery 2>/dev/null | grep -E "CycleCount|DesignCapacity|MaxCapacity|Temperature|\"Voltage\"|PermanentFailureStatus|BatteryInstalled|IsCharging|ExternalConnected"'

    sub "Sleep / wake history"
    run -m 120 -l "recent sleep & wake events" 'pmset -g log 2>/dev/null | grep -iE "sleep|wake|darkwake|failure" | tail -120'
    run -m 40 -l "wake reasons" 'pmset -g log 2>/dev/null | grep -i "wake from" | tail -40'

    if deep && { [ "$IS_ROOT" = 1 ] || [ "$SUDO_AVAILABLE" = 1 ]; }; then
        sub "Live power/thermal sample (deep mode)"
        run -r -t 60 -m 120 -l "powermetrics single 1s sample" \
            'powermetrics -n 1 -i 1000 --samplers cpu_power,thermal,smc 2>&1 | head -120'
    fi
}

mod_processes() {
    section processes "Running processes, load & memory"

    sub "Load & memory pressure"
    run "uptime"
    run -m 40 "vm_stat"
    run "sysctl vm.swapusage"
    run -m 40 -l "swap files on disk" 'ls -lh /private/var/vm 2>&1'
    local swap_used
    swap_used="$(sysctl -n vm.swapusage 2>/dev/null | sed -n 's/.*used = \([0-9.]*\)M.*/\1/p')"
    if [ -n "${swap_used:-}" ]; then
        fact swap.used_mb "$swap_used"
        case "$swap_used" in
            *[!0-9.]*) : ;;
            *) if [ "${swap_used%%.*}" -gt 4096 ] 2>/dev/null; then
                   finding WARN "Heavy swap usage (${swap_used} MB)" "Sustained swap indicates memory pressure; expect beachballs and slow app launches."
               fi ;;
        esac
    fi

    sub "Top processes"
    run -t 60 -m 60 -l "top by CPU (2 samples)" \
        'top -l 2 -n 20 -o cpu -stats pid,command,cpu,mem,threads,state 2>/dev/null | tail -30'
    run -m 40 -l "ps: top 25 by CPU" 'ps -Ao pid,ppid,user,%cpu,%mem,rss,etime,command -r | head -26'
    run -m 40 -l "ps: top 25 by RSS" 'ps -Ao pid,ppid,user,%cpu,%mem,rss,etime,command -m | head -26'
    run -m 30 -l "total process count" 'ps -Ax | wc -l'

    sub "Notable daemons"
    run -m 60 -l "management / identity / security daemons" \
        'ps auxww | grep -iE "mdmclient|jamf|intune|jumpcloud|AppSSO|opendirectoryd|trustd|nesessionmanager|softwareupdated|CrashPlan|falcon|crowdstrike|defender|wdav|sentinel|carbonblack|sophos" | grep -v grep'

    sub "Open file / socket pressure"
    run "sysctl kern.maxfiles kern.maxfilesperproc kern.num_files"
    run -r -m 30 -l "open file count" 'lsof -n 2>/dev/null | wc -l'

    sub "Recent process exits & spins"
    run -m 60 -l "spindump/hang reports on disk" \
        'ls -lt /Library/Logs/DiagnosticReports 2>/dev/null | grep -iE "spin|hang|wakeups|cpu_resource" | head -30'
}

mod_software() {
    section software "Installed software"

    sub "Applications"
    run_fn -t 180 -m 500 "applications with versions and bundle identifiers" _fn_applications

    sub "Installed packages (receipts)"
    run -m 200 -l "package receipts (most recent 200)" 'pkgutil --pkgs | sort | head -200'
    run -m 40 -l "receipt count" 'pkgutil --pkgs | wc -l'

    sub "Developer & package managers"
    run "xcode-select -p"
    run "brew --version"
    run -m 120 -l "Homebrew formulae/casks with versions" 'brew list --versions 2>&1 | head -120'
    run -m 60 "brew config"
    if deep; then
        run -t 180 -m 120 "brew doctor"
    fi
    run "python3 --version"
    run "node --version"

    sub "Security / EDR agents present"
    run -m 60 -l "known EDR & VPN client footprints" \
        'ls -d /Applications/*.app 2>/dev/null | grep -iE "crowdstrike|falcon|defender|sentinel|carbon|sophos|eset|malwarebytes|cisco|umbrella|globalprotect|zscaler|netskope|forticlient|tunnelblick|viscosity|openvpn|nordlayer|tailscale" '
    run -m 60 -l "network system extensions (content filters, DNS proxies, VPN)" \
        'systemextensionsctl list 2>/dev/null | grep -iE "network|filter|dns|proxy|vpn"'

    if deep; then
        sub "Code signatures of installed applications (deep mode)"
        run_fn -t 300 -m 600 "codesign authorities for /Applications" _fn_app_signatures
    fi
}

mod_updates() {
    section updates "Software update state"

    sub "Available updates"
    if fast; then
        run -t 60 -m 60 "softwareupdate --list --no-scan"
    else
        run -t 240 -m 80 "softwareupdate --list"
    fi
    if grep -qiE 'restart|recommended' "$RUN_OUT" 2>/dev/null; then
        finding INFO "Software updates are pending" "\`softwareupdate --list\` reports available updates; some may require a restart."
    fi

    sub "Update configuration"
    run -m 60 "defaults read /Library/Preferences/com.apple.SoftwareUpdate"
    run -m 40 -l "managed software update policy (MDM)" \
        'plutil -p "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist" 2>&1'
    run -m 40 -l "App Store / commerce prefs" 'plutil -p /Library/Preferences/com.apple.commerce.plist 2>&1'
    run -r -m 40 "softwareupdate --list-full-installers"

    sub "Install history"
    run -t 120 -m 200 -l "install history (most recent entries)" \
        'system_profiler SPInstallHistoryDataType 2>/dev/null | tail -200'
    run -m 60 -l "OS installer receipts" 'ls -la /Library/Receipts/InstallHistory.plist 2>&1'

    sub "Deferred / managed OS updates"
    run -r -m 60 -l "MDM-declared software update status" \
        'plutil -p /var/db/ConfigurationProfiles/Settings/com.apple.SoftwareUpdate.plist 2>&1'
    run -m 60 -l "softwareupdated activity" \
        'log show --last 6h --style compact --predicate '"'"'process == "softwareupdated"'"'"' 2>&1 | tail -60'
}

mod_logs() {
    section logs "Diagnostics: crashes, panics & unified log excerpts"

    sub "Crash & diagnostic reports on disk"
    run_fn -m 100 "DiagnosticReports directory listings" _fn_crash_reports
    run_fn -m 100 "most recent kernel panic report" _fn_latest_panic
    if grep -qiE 'panic\(' "$RUN_OUT" 2>/dev/null; then
        finding CRIT "A kernel panic report is present" "See the panic excerpt in the logs section; note the panicking extension/driver."
    fi
    run_fn -t 90 -m 250 "recent application crash reports (headers)" _fn_recent_crashes

    sub "Shutdown causes"
    run -m 40 -l "shutdown causes from the power log" \
        'log show --last 7d --style compact --predicate '"'"'eventMessage CONTAINS "Previous shutdown cause"'"'"' 2>&1 | tail -20'

    if fast; then
        sub "Unified log excerpts"
        note "Skipped in \`--fast\` mode. Re-run without --fast (or with --deep) to include unified log excerpts."
        return 0
    fi

    sub "Unified log: errors and faults"
    export PRED='messageType == error OR messageType == fault'
    run -t 240 -m 400 -l "system-wide errors & faults (last $LOG_WINDOW)" \
        'log show --last '"$LOG_WINDOW"' --style compact --predicate "$PRED" 2>&1 | tail -400'

    sub "Unified log: networking & trust"
    export PRED='process == "trustd" OR process == "nesessionmanager" OR subsystem CONTAINS[c] "network" AND messageType == error'
    run -t 180 -m 200 -l "trust evaluation & networking errors (last $LOG_WINDOW)" \
        'log show --last '"$LOG_WINDOW"' --style compact --predicate "$PRED" 2>&1 | tail -200'

    sub "Unified log: authentication & security"
    export PRED='process == "opendirectoryd" OR process == "authd" OR process == "securityd" OR process == "loginwindow"'
    run -t 180 -m 200 -l "authentication subsystem (last $LOG_WINDOW)" \
        'log show --last '"$LOG_WINDOW"' --style compact --predicate "$PRED" 2>&1 | tail -200'

    sub "Log collection configuration"
    run -m 30 "log config --status"
    run -m 40 -l "log archive sizes" 'ls -lh /var/db/diagnostics 2>&1 | head -20'
}

mod_peripherals() {
    section peripherals "Displays, peripherals, printers & audio"

    sub "Displays"
    run -t 90 -m 120 "system_profiler SPDisplaysDataType"

    sub "USB & Thunderbolt"
    run -t 90 -m 200 "system_profiler SPUSBDataType"
    run -t 90 -m 120 "system_profiler SPThunderboltDataType"

    sub "Bluetooth"
    run -t 90 -m 200 "system_profiler SPBluetoothDataType"

    sub "Audio & camera"
    run -t 90 -m 150 "system_profiler SPAudioDataType"
    run -t 60 -m 60 "system_profiler SPCameraDataType"

    sub "Printers"
    run -m 60 "lpstat -p -d"
    run -m 60 -l "CUPS printers" 'lpstat -t 2>&1 | head -60'
    run -t 90 -m 100 "system_profiler SPPrintersDataType"
}

mod_certs() {
    section certs "Keychains, certificates & trust settings"
    note "Only certificate metadata is collected. No private keys, passwords or keychain secrets are read, and no dialog is triggered."

    sub "Keychains & identities"
    run_fn -t 120 -m 250 "keychain list, certificate labels and identities" _fn_keychain_certs

    sub "Certificate validity windows (System keychain)"
    run_fn -t 120 -m 110 "System keychain certificate expiry state" _fn_expiring_certs
    if grep -q '^EXPIRED' "$RUN_OUT" 2>/dev/null; then
        finding WARN "Expired certificates are present in the System keychain" \
            "Check whether any of them is the MDM identity, a SCEP/device certificate or an internal CA — an expired one silently breaks enrollment and 802.1X."
    fi
    if grep -q '^<90d' "$RUN_OUT" 2>/dev/null; then
        finding INFO "Certificates in the System keychain expire within 90 days" \
            "See the table above; renew any MDM/SCEP/802.1X identity before it lapses."
    fi

    sub "Custom trust settings (a common TLS-interception fingerprint)"
    local mitm_re='fortinet|fortigate|zscaler|netskope|palo ?alto|bluecoat|blue coat|sophos|umbrella|forcepoint|websense|check ?point|sonicwall|watchguard|barracuda|kaspersky|mitm'
    run -r -m 200 -l "admin (machine-wide) trust settings" 'security dump-trust-settings -d 2>&1'
    if grep -qiE "$mitm_re" "$RUN_OUT" 2>/dev/null; then
        finding WARN "A root CA associated with TLS inspection is trusted machine-wide" \
            "An inspection-appliance root was found in the admin trust settings. Confirm the Apple and Microsoft identity/management endpoints are excluded from inspection."
    fi
    run -m 200 -l "user trust settings" 'security dump-trust-settings 2>&1'
    if grep -qiE "$mitm_re" "$RUN_OUT" 2>/dev/null; then
        finding WARN "A root CA associated with TLS inspection is trusted by the console user" \
            "An inspection-appliance root was found in the user's trust settings."
    fi

    sub "MDM identity & device certificates"
    run -r -m 80 -l "certificates whose label mentions MDM/Device/Intune/Jamf" \
        'security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -iE "labl|alis" | grep -iE "mdm|device|intune|jamf|jumpcloud|microsoft|workplace|scep|apple" | head -60'
}

mod_time() {
    section time "Date, time & time synchronisation"
    note "Clock skew silently breaks certificate validation, Kerberos, Entra ID token issuance and MDM check-in."

    run "date"
    run -l "UTC time" 'date -u'
    run "systemsetup -gettimezone"
    run -r "systemsetup -getusingnetworktime"
    run -r "systemsetup -getnetworktimeserver"
    run -m 40 -l "timed configuration" 'plutil -p /Library/Preferences/com.apple.timed.plist 2>&1'
    run -m 20 -l "time sync state files" 'ls -la /var/db/timed 2>&1'
    run -m 40 -l "timed / NTP unified log" \
        'log show --last 6h --style compact --predicate '"'"'process == "timed"'"'"' 2>&1 | tail -40'
    if grep -qiE 'failed|unreachable|no server|timed out' "$RUN_OUT" 2>/dev/null; then
        finding WARN "Time synchronisation errors appear in the log" \
            "The \`timed\` daemon reported failures. Clock skew breaks certificate validation, Kerberos and Entra ID token issuance."
    fi
}

mod_tests() {
    section tests "Harmless functional tests"
    note "Every test below is read-only and bounded. Nothing is written to disk, no service is restarted, and no configuration is changed."

    sub "Filesystem readability spot-checks"
    run -m 30 -l "can the console user read their own home?" 'ls -la "'"$USER_HOME"'" >/dev/null 2>&1 && echo OK: readable || echo FAIL: not readable'
    run -m 30 -l "is the system volume mounted read-only (expected on macOS 11+)?" 'mount | grep " / "'
    run -m 30 -l "is /tmp writable by the current user? (informational, nothing is written)" \
        'test -w /tmp && echo "OK: /tmp is writable" || echo "WARN: /tmp is not writable"'

    sub "Directory service responsiveness"
    run -t 30 -m 20 -l "dscl round-trip for the console user" \
        'time dscl . -read "/Users/'"$CONSOLE_USER"'" RecordName >/dev/null'
    run -t 30 -m 20 -l "dscacheutil round-trip" 'time dscacheutil -q user -a name "'"$CONSOLE_USER"'" >/dev/null'

    sub "Keychain responsiveness (no secrets read)"
    run -t 30 -m 20 -l "keychain search list round-trip" 'time security list-keychains >/dev/null'

    if [ "$DO_NETWORK" = 1 ]; then
        sub "Network latency summary"
        run -t 60 -m 40 -l "HTTPS handshake to Apple" \
            'curl -sS -o /dev/null --max-time 15 -w "dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total} code=%{http_code}\n" https://www.apple.com/'
        run -t 60 -m 40 -l "HTTPS handshake to Microsoft Entra ID" \
            'curl -sS -o /dev/null --max-time 15 -w "dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total} code=%{http_code}\n" https://login.microsoftonline.com/'
    fi

    if deep; then
        sub "CPU throughput (deep mode)"
        run_fn -t 90 -m 40 "openssl SHA-256 throughput" _fn_cpu_bench

        sub "Sequential read throughput (deep mode)"
        note "Reads an existing large system file into /dev/null. Nothing is written."
        run_fn -t 120 -m 40 "256 MiB sequential read from the boot volume" _fn_disk_read_bench
    fi
}

# ===========================================================================
# Report assembly
# ===========================================================================

count_findings() {
    awk -F'\t' -v s="$1" '$1==s{n++} END{printf "%d", n+0}' "$FINDINGS_FILE" 2>/dev/null
}

render_findings() {
    local sev label n s title detail
    if [ ! -s "$FINDINGS_FILE" ]; then
        printf '%s\n\n' "No automated red flag was raised. This does **not** mean the machine is healthy — it means none of the scripted heuristics tripped. Read the sections below."
        return 0
    fi
    for sev in CRIT WARN INFO; do
        case "$sev" in
            CRIT) label="Critical" ;;
            WARN) label="Warning" ;;
            INFO) label="Informational" ;;
        esac
        n="$(count_findings "$sev")"
        [ "${n:-0}" = "0" ] && continue
        printf '### %s (%s)\n\n' "$label" "$n"
        while IFS=$'\t' read -r s title detail; do
            [ "$s" = "$sev" ] || continue
            printf -- '- **%s**  \n  %s\n' "$title" "$detail"
        done <"$FINDINGS_FILE"
        printf '\n'
    done
}

render_header() {
    local end_epoch dur priv
    end_epoch="$(date +%s 2>/dev/null || echo 0)"
    dur=$(( end_epoch - START_EPOCH )); [ "$dur" -lt 0 ] && dur=0

    if [ "$IS_ROOT" = 1 ]; then priv="root"
    elif [ "$SUDO_AVAILABLE" = 1 ]; then priv="user + cached sudo"
    else priv="unprivileged user"
    fi

    printf '# macOS system audit — %s\n\n' "$HOSTNAME_SHORT"
    printf '<!-- generated by %s v%s -->\n\n' "$SCRIPT_NAME" "$VERSION"
    printf '| | |\n|---|---|\n'
    printf '| Host | %s |\n' "$HOSTNAME_SHORT"
    printf '| Model | %s |\n' "$(getfact hw.model)"
    printf '| macOS | %s (%s) |\n' "$(getfact os.version)" "$(getfact os.build)"
    printf '| Console user | %s |\n' "$CONSOLE_USER"
    printf '| Collected | %s |\n' "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)"
    printf '| Collector | %s v%s, mode `%s` |\n' "$SCRIPT_NAME" "$VERSION" "$MODE"
    printf '| Privilege | %s |\n' "$priv"
    printf '| Commands run | %s (failed: %s, timed out: %s, skipped: %s) |\n' \
        "$CMD_COUNT" "$CMD_FAILED" "$CMD_TIMEOUT" "$CMD_SKIPPED"
    printf '| Duration | %ss |\n' "$dur"
    printf '| Redaction | %s |\n' "$([ "$REDACT" = 1 ] && echo 'on (serials, UUIDs, MACs, emails masked)' || echo 'off')"
    printf '| Network probes | %s |\n' "$([ "$DO_NETWORK" = 1 ] && echo enabled || echo disabled)"
    [ "$ABORTED" = 1 ] && printf '| **Status** | **INTERRUPTED — this report is partial** |\n'
    printf '\n'

    cat <<'EOF'
## How to read this report

This is a **read-only** snapshot. Nothing on the machine was modified: no
setting was changed, no file moved or deleted, no service restarted, no cache
cleared. Every entry below is the verbatim output of a query command, printed
under the exact command that produced it, so any statement in this report can
be re-verified by running that single command.

Conventions:

- A `####` heading holds the command that was run; the fenced block beneath it
  is that command's combined stdout and stderr.
- `> exit=N` means the command exited non-zero. That is frequently meaningful
  data (feature absent, permission denied, service not configured) rather than
  a collection error.
- `> skipped: ...` means the command was not run at all — the binary is not
  present, or it needs root and this run was unprivileged.
- `> truncated to first N of M lines` means output was capped. Re-run with a
  larger `--max-lines`, or with `--deep`.
- Long opaque tokens and any private-key blocks are always elided, regardless
  of the `--redact` setting.

EOF

    if [ "$IS_ROOT" != 1 ]; then
        cat <<'EOF'
**This run was not privileged**, so root-only data is missing: the full
configuration-profile list, `mdmclient QuerySecurityInfo`, bootstrap token
status, system TCC grants, `wdutil info`, `pfctl` rules and admin trust
settings. Re-run with `sudo` for a complete picture.

EOF
    fi

    printf '## Findings\n\n'
    printf '%s\n\n' "Automated heuristics only — treat them as leads, not conclusions."
    render_findings

    printf '## Contents\n\n'
    local s
    for s in $ALL_SECTIONS; do
        want "$s" || continue
        printf -- '- %s\n' "$s"
    done
    printf '\n'
}

finalize() {
    render_header >"$HEADER"

    local target
    if [ "$TO_STDOUT" = 1 ]; then
        cat "$HEADER" "$BODY"
        progress ""
        progress "== report written to stdout ($CMD_COUNT commands)"
        return 0
    fi

    if [ -n "$OUT_PATH" ]; then
        if [ -d "$OUT_PATH" ]; then
            target="${OUT_PATH%/}/macos-audit-${HOSTNAME_SAFE}-${STAMP}.md"
        else
            target="$OUT_PATH"
        fi
    else
        local dir=""
        for dir in "$USER_HOME/Desktop" "$USER_HOME" "${TMPDIR:-/tmp}"; do
            [ -d "$dir" ] && [ -w "$dir" ] && break
            dir=""
        done
        [ -z "$dir" ] && dir="/tmp"
        target="$dir/macos-audit-${HOSTNAME_SAFE}-${STAMP}.md"
    fi

    if ! cat "$HEADER" "$BODY" >"$target" 2>/dev/null; then
        progress "!! could not write $target — falling back to stdout"
        cat "$HEADER" "$BODY"
        return 1
    fi
    chmod 600 "$target" 2>/dev/null

    # Make the file belong to the console user when running under sudo.
    if [ "$IS_ROOT" = 1 ] && [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER" "$target" 2>/dev/null
    fi

    local size
    size="$(ls -lh "$target" 2>/dev/null | awk '{print $5}')"
    progress ""
    progress "=============================================================="
    progress "  Report : $target"
    progress "  Size   : ${size:-?}   Commands: $CMD_COUNT (failed $CMD_FAILED, timeout $CMD_TIMEOUT, skipped $CMD_SKIPPED)"
    progress "  Flags  : CRIT $(count_findings CRIT) · WARN $(count_findings WARN) · INFO $(count_findings INFO)"
    progress "=============================================================="
    progress ""
    progress "  Review it before sharing:   open -e \"$target\""
    progress "  Copy it to the clipboard:   pbcopy < \"$target\""
    [ "$REDACT" = 1 ] || progress "  Re-run with --redact to mask serials, UUIDs, MACs and email addresses."
    progress ""
    return 0
}

# ===========================================================================
# Main
# ===========================================================================
main() {
    START_EPOCH="$(date +%s 2>/dev/null || echo 0)"

    progress "=============================================================="
    progress "  $SCRIPT_NAME v$VERSION — read-only macOS audit (mode: $MODE)"
    progress "  Host: $HOSTNAME_SHORT   Console user: $CONSOLE_USER"
    progress "=============================================================="

    _selftest_scrub
    init_sudo
    if [ "$IS_ROOT" != 1 ] && [ "$SUDO_AVAILABLE" != 1 ]; then
        progress "-- running unprivileged: root-only queries will be marked as skipped"
        progress "   (re-run with 'sudo' or '--sudo' for full coverage)"
    fi

    local s
    for s in $ALL_SECTIONS; do
        want "$s" || continue
        [ "$ABORTED" = 1 ] && break
        case "$s" in
            meta)        mod_meta ;;
            hardware)    mod_hardware ;;
            os)          mod_os ;;
            security)    mod_security ;;
            mdm)         mod_mdm ;;
            sso)         mod_sso ;;
            users)       mod_users ;;
            network)     mod_network ;;
            storage)     mod_storage ;;
            power)       mod_power ;;
            processes)   mod_processes ;;
            software)    mod_software ;;
            updates)     mod_updates ;;
            logs)        mod_logs ;;
            peripherals) mod_peripherals ;;
            certs)       mod_certs ;;
            time)        mod_time ;;
            tests)       mod_tests ;;
        esac
    done

    finalize
}

main
