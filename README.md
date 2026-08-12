# scripts

Operational scripts for macOS support and remediation work.

| Script | Purpose | Mutates the system? |
|---|---|---|
| [`macos-audit.sh`](#macos-auditsh) | Read-only system audit that produces one large Markdown report for human or AI diagnosis | **No** |
| `jc-recovery-fix.sh` | Recovery-environment fix that renames a user's cache/saved-state/loginwindow prefs | Yes — run only from Recovery, on the named volume |

---

## `macos-audit.sh`

A read-only macOS collector. It runs ~230 query commands and writes a single
Markdown report containing hardware, OS, security posture, MDM enrollment and
configuration profiles, Platform SSO / directory state, users, network,
storage, power, processes, installed software, update state, recent crashes
and unified-log excerpts — plus an automatically generated findings summary at
the top.

It is built for the case where you want to hand a machine's full context to
someone (or something) that cannot see the machine.

### Quick start

```bash
# copy the script to the Mac, then:
sudo bash macos-audit.sh
```

The report lands on the Desktop as `macos-audit-<host>-<timestamp>.md`. The
script prints the path when it finishes.

```bash
bash macos-audit.sh                  # unprivileged; root-only data is marked skipped
sudo bash macos-audit.sh             # full coverage (recommended)
bash macos-audit.sh --sudo           # prompt once for sudo, then collect
bash macos-audit.sh --stdout > a.md  # report to stdout
bash macos-audit.sh --redact         # mask serials, UUIDs, MACs and email addresses
bash macos-audit.sh --fast           # ~1 min: skips unified-log queries
bash macos-audit.sh --deep           # everything, wider log windows, benchmarks
bash macos-audit.sh --only mdm,sso   # just the management/identity sections
bash macos-audit.sh --no-network     # no outbound request at all
bash macos-audit.sh --help
```

Sections: `meta hardware os security mdm sso users network storage power
processes software updates logs peripherals certs time tests`.

### What "read-only" means here

The only thing the script writes is its own report file, plus a temp directory
under `$TMPDIR` that is deleted on exit.

- No setting is changed, no file is moved or deleted, no service is started,
  stopped or restarted, no cache is cleared, no repair is attempted.
- Only query/getter subcommands are used. Anything that mutates state
  (`softwareupdate -i`, `fdesetup enable`, `sysadminctl -addUser`, `pmset -a`,
  `systemsetup -set*`, `jamf policy`, `profiles -R`, `launchctl load|bootout`,
  `defaults write`, `diskutil erase|repair`) is deliberately absent, and
  flags are never guessed at on tools that also have destructive verbs
  (notably `app-sso`, which can trigger or tear down SSO registration).
- `sudo` is only ever used non-interactively (`sudo -n`) unless you pass
  `--sudo`, and only for read-only commands.
- `osascript` / AppleEvents are never used, so the script triggers no
  Automation or Full Disk Access consent dialog.
- Outbound probes (ICMP, DNS, HTTPS timing, TLS chain inspection) only touch
  Apple, Cloudflare, Google DNS and Microsoft identity/management endpoints,
  and `--no-network` removes them entirely.

### Robustness

- **Nothing can hang the run.** Every command executes in a background process
  tree with a wall-clock timeout (`--timeout`, default 45s); on expiry the
  whole tree is killed with `TERM` then `KILL`, and the entry is marked
  `TIMED OUT`.
- **Missing tools degrade, they don't fail.** A command whose binary is absent
  is recorded as skipped with the reason. Non-zero exits are reported and kept,
  because "permission denied" or "not configured" is itself the answer.
- **Ctrl-C still gives you a report.** SIGINT/SIGTERM stops collection and
  assembles a partial report flagged `INTERRUPTED`.
- **Output is bounded.** Per-command line and byte caps keep the report
  pasteable; truncation is always stated in the entry.
- **Secrets are elided unconditionally.** Long opaque tokens (e.g. the
  `fmm-mobileme-token-FMM` in `nvram -p`), private-key blocks and
  `KEY=`/`TOKEN=`/`SECRET=`-shaped assignments never reach the report,
  independent of `--redact`.
- **bash 3.2 and BSD userland only.** Runs on the stock `/bin/bash` with no
  dependencies. The output filters avoid GNU-only `sed` constructs and
  self-test at startup, falling back to pass-through if the platform's `sed`
  rejects them.
- **Losing sudo mid-run is handled.** If the cached credential expires part-way
  through, the script says so instead of silently emitting empty sections.

### Report layout

The report opens with a fact table, a short "how to read this" note, an
automatically generated **Findings** list (critical / warning / informational),
and a table of contents. Then every section, and inside it every command as:

````
#### `csrutil status`

> _exit=1 · truncated to first 200 of 812 lines_

```text
System Integrity Protection status: enabled.
```
````

Every claim in the report is attributable to exactly one command, so anything
can be re-verified by running that single command.

Findings are heuristics, not conclusions. They currently cover SIP, FileVault,
Gatekeeper, the application firewall, disk space, uptime, battery condition,
swap pressure, SMART status, kernel panics, third-party kexts, MDM enrollment
state, Platform SSO registration state, TLS interception (both by observed
certificate issuer and by locally trusted inspection roots), captive portals,
clock-sync errors, expired/expiring System-keychain certificates and pending
updates.

### Sharing the report

The report contains detailed configuration data: hostnames, serial numbers,
usernames and UPNs, network configuration, installed software and directory
records. Read it before sending it anywhere. `--redact` masks serial numbers,
UUIDs, MAC addresses and email addresses, at the cost of making MDM and SSO
issues harder to diagnose.

```bash
open -e ~/Desktop/macos-audit-*.md    # review
pbcopy < ~/Desktop/macos-audit-*.md   # copy to clipboard
```
