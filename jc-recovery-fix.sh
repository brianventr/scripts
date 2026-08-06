#!/bin/sh
#
#  jc-recovery-fix.sh -- Ventr Corporation
#
#  Run from macOS RECOVERY Terminal on a JumpCloud-damaged Mac.
#  Finds the system disk automatically, then repairs all three login layers:
#    1. Strips jcagent/jumpcloud lines from every pam.d file (keeps .bak copies)
#    2. Removes the JumpCloud SecurityAgent login plugin bundles
#    3. Deletes auth.db so macOS rebuilds Apple-default authorization at boot
#
#  Ends with ONE readable result line:
#    RESULT: OK           -> restart the Mac normally; fixed
#    RESULT: LOCKED-DISK  -> mount the data volume in Disk Utility, run again
#    RESULT: NOT-OK       -> read the lines above it to the technician
#
#  Designed for delivery via a short link:  curl -L -o fix <url>  ;  sh fix
#

FOUND=0
BAD=0

echo ""
echo "Ventr JumpCloud Recovery Fix v1.0"
SER=`system_profiler SPHardwareDataType 2>/dev/null | grep "Serial Number" | awk -F": " '{print $2}'`
[ -n "$SER" ] && echo "Serial: $SER"
echo ""

for v in /Volumes/*; do
    d="$v/private/etc/pam.d"
    [ -d "$d" ] || continue
    FOUND=1
    echo "Working on: $v"

    # --- 1. PAM cleanup -------------------------------------------------
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        case "$f" in *.bak) continue ;; esac
        if grep -qiE 'jcagent|jumpcloud' "$f" 2>/dev/null; then
            sed -i '.bak' '/jcagent/d;/jumpcloud/d' "$f"
            echo "  cleaned: $f"
        fi
    done

    # verify: no live references remain
    for f in "$d"/*; do
        case "$f" in *.bak) continue ;; esac
        [ -f "$f" ] || continue
        if grep -qiE 'jcagent|jumpcloud' "$f" 2>/dev/null; then
            echo "  PROBLEM: references still present in $f"
            BAD=1
        fi
    done

    # verify: authorization file still has auth lines
    if [ -f "$d/authorization" ]; then
        n=`grep -c '^auth' "$d/authorization" 2>/dev/null`
        if [ "$n" -lt 1 ] 2>/dev/null; then
            echo "  PROBLEM: $d/authorization has no auth lines"
            BAD=1
        fi
    fi

    # --- 2. Login plugin bundles ---------------------------------------
    rm -rf "$v/Library/Security/SecurityAgentPlugins/JCLoginPlugin.bundle" \
           "$v/Library/Security/SecurityAgentPlugins/jumpcloud-loginwindow.bundle" 2>/dev/null
    echo "  login plugins: removed (if present)"

    # --- 3. Stale PAM module + authorization database -------------------
    rm -f "$v/usr/local/lib/security/libpam_jcagent.so" 2>/dev/null
    rm -f "$v/private/var/db/auth.db" \
          "$v/private/var/db/auth.db-shm" \
          "$v/private/var/db/auth.db-wal" 2>/dev/null
    echo "  authorization database: reset (rebuilds at next start)"
done

echo ""
if [ "$FOUND" -eq 0 ]; then
    echo "No system disk found. It is probably locked."
    echo "Open Disk Utility from the Utilities window, click the disk named"
    echo "Macintosh HD - Data on the left, click Mount at the top, type the"
    echo "user password, close Disk Utility, then run this again."
    echo ""
    echo "RESULT: LOCKED-DISK"
    exit 2
fi

if [ "$BAD" -eq 1 ]; then
    echo "RESULT: NOT-OK"
    exit 1
fi

echo "All repairs done. Restart the Mac now: Apple menu, then Restart."
echo ""
echo "RESULT: OK"
exit 0
