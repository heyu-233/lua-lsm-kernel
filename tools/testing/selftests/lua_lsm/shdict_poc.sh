#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# securityfs shared dict get/set PoC
#
# Loads shdict_poc.lua as the "demo" module, triggers one file_open hook to
# create the "runtime" shared dict, then drives every command of
# /sys/kernel/security/lua/shdict over a single file descriptor.
#
# Exercises (in order):
#   1. bool/number/plain-string/NUL-string round-trips
#   2. same-key overwrite is visible immediately
#   3. blocked_path=/tmp/blocked denies that path only
#   4. re-setting blocked_path changes policy behavior without reload
#   5. unknown module/dict/key -> -ENOENT (get and set)
#   6. bad types, odd/non-hex strings, over-limit inputs -> -EINVAL/-E2BIG
#   7. unprivileged open denied; CAP_MAC_ADMIN enforced per op (-EPERM)
#   7c. Lua hook reads a NUL-containing string written by securityfs
#   7d. lightuserdata values are refused (-EOPNOTSUPP), never exported
#   7e. Lua-side string longer than the response buffer -> -E2BIG
#   7f. Lua nil delete recycles the node (verified via kvcache.nusage)
#   8. module pinned in a busy task -> unregister -EBUSY, then get/set
#      on the ZOMBIE module returns -ESHUTDOWN without touching the dict
#
# Requires: CONFIG_SECURITY_LUA_LSM, securityfs mounted, CAP_MAC_ADMIN.
# Run in the lua-lsm QEMU initramfs (see README.md).
#
# Exit status: 0 = all checks passed, 1 = at least one check failed.

set -u

BASE=/sys/kernel/security/lua
SHDICT=$BASE/shdict
POLICY=${1:-$(dirname -- "$0")/shdict_poc.lua}
MODULE=demo
DICT=runtime

PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# shdict_send <command...>: write one command to the shared fd (3) and
# store the one-line response in $resp.
shdict_send() {
	printf '%s\n' "$*" >&3 2>/dev/null
	IFS= read -r resp <&3 2>/dev/null || resp=
}

check_resp() { # <expected> <description>
	if [ "$resp" = "$1" ]; then
		ok "$2"
	else
		bad "$2 (expected '$1', got '$resp')"
	fi
}

# make_a_run <min-len>: sets $a_run to a string of 'a' whose length is
# 2^k >= <min-len>.
make_a_run() {
	a_run=a
	while [ ${#a_run} -lt "$1" ]; do
		a_run=$a_run$a_run
	done
}

echo "== Lua-LSM securityfs shared dict PoC =="

[ -f "$POLICY" ] || { bad "policy $POLICY not found"; exit 1; }
[ -w "$SHDICT" ] || { bad "$SHDICT missing (securityfs not mounted?)"; exit 1; }

echo "-- 0. load policy, trigger one hook to create the shared dict --"
ls -l "$BASE"
cat "$POLICY" > "$BASE/register" || { bad "module register failed"; exit 1; }
cat /proc/version > /dev/null || { bad "hook trigger failed"; exit 1; }
ok "module registered, shared dict created by a real file_open"

exec 3<>"$SHDICT" || { bad "cannot open $SHDICT"; exit 1; }

echo "-- 1. bool / number / string (incl. embedded NUL) round-trips --"
shdict_send set "$MODULE" "$DICT" flag bool 1
check_resp OK "set bool 1"
shdict_send get "$MODULE" "$DICT" flag
check_resp "bool 1" "get bool 1"
shdict_send set "$MODULE" "$DICT" flag bool 0
check_resp OK "set bool 0"
shdict_send get "$MODULE" "$DICT" flag
check_resp "bool 0" "get bool 0"

shdict_send set "$MODULE" "$DICT" n number 42
check_resp OK "set number 42"
shdict_send get "$MODULE" "$DICT" n
check_resp "number 42" "get number 42"
shdict_send set "$MODULE" "$DICT" n number -7
check_resp OK "set number -7"
shdict_send get "$MODULE" "$DICT" n
check_resp "number -7" "get number -7"

# "hello" = 68656c6c6f ; "a\0b" = 610062
shdict_send set "$MODULE" "$DICT" s string 68656c6c6f
check_resp OK "set string hello"
shdict_send get "$MODULE" "$DICT" s
check_resp "string 68656c6c6f" "get string hello"
shdict_send set "$MODULE" "$DICT" s2 string 610062
check_resp OK "set string a<NUL>b"
shdict_send get "$MODULE" "$DICT" s2
check_resp "string 610062" "get string with embedded NUL"

echo "-- 2. overwrite the same key, new value visible immediately --"
shdict_send set "$MODULE" "$DICT" ov string 01
check_resp OK "set ov=01"
shdict_send set "$MODULE" "$DICT" ov string 02
check_resp OK "set ov=02 (same key)"
shdict_send get "$MODULE" "$DICT" ov
check_resp "string 02" "overwritten value visible immediately"

echo "-- 3. blocked_path=/tmp/blocked denies that path only --"
touch /tmp/blocked /tmp/blocked2 /tmp/plain || { bad "touch fixtures"; exit 1; }
# /tmp/blocked = 2f746d702f626c6f636b6564
shdict_send set "$MODULE" "$DICT" blocked_path string 2f746d702f626c6f636b6564
check_resp OK "set blocked_path=/tmp/blocked"
if cat /tmp/blocked > /dev/null 2>&1; then
	bad "open /tmp/blocked should be denied by the hook"
else
	ok "open /tmp/blocked denied by the hook"
fi
if cat /tmp/plain > /dev/null 2>&1; then
	ok "open /tmp/plain still allowed"
else
	bad "open /tmp/plain should still be allowed"
fi

echo "-- 4. re-set blocked_path, policy changes without module reload --"
# /tmp/blocked2 = 2f746d702f626c6f636b656432
shdict_send set "$MODULE" "$DICT" blocked_path string 2f746d702f626c6f636b656432
check_resp OK "set blocked_path=/tmp/blocked2"
if cat /tmp/blocked > /dev/null 2>&1; then
	ok "open /tmp/blocked allowed after re-set"
else
	bad "open /tmp/blocked should be allowed after re-set"
fi
if cat /tmp/blocked2 > /dev/null 2>&1; then
	bad "open /tmp/blocked2 should now be denied"
else
	ok "open /tmp/blocked2 denied after re-set"
fi

echo "-- 5. unknown module / dict / key -> -ENOENT (get and set) --"
shdict_send get nosuchmod "$DICT" k
check_resp "ERR -ENOENT" "get: unknown module"
shdict_send get "$MODULE" nosuchdict k
check_resp "ERR -ENOENT" "get: unknown dict"
shdict_send get "$MODULE" "$DICT" nosuchkey
check_resp "ERR -ENOENT" "get: unknown key"
shdict_send set nosuchmod "$DICT" k bool 1
check_resp "ERR -ENOENT" "set: unknown module"
shdict_send set "$MODULE" nosuchdict k bool 1
check_resp "ERR -ENOENT" "set: unknown dict"

echo "-- 6. format and size errors --"
shdict_send set "$MODULE" "$DICT" k bogus 1
check_resp "ERR -EINVAL" "unknown value type"
shdict_send set "$MODULE" "$DICT" k bool 2
check_resp "ERR -EINVAL" "bool must be 0 or 1"
shdict_send set "$MODULE" "$DICT" k number 1x
check_resp "ERR -EINVAL" "malformed number"
shdict_send set "$MODULE" "$DICT" k string abc
check_resp "ERR -EINVAL" "odd-length hex string"
shdict_send set "$MODULE" "$DICT" k string zz
check_resp "ERR -EINVAL" "non-hex string"
make_a_run 129
shdict_send set "$MODULE" "$DICT" "$a_run" bool 1
check_resp "ERR -E2BIG" "key longer than 128 bytes"
make_a_run 2048
a_run=${a_run}aa
shdict_send set "$MODULE" "$DICT" big string "$a_run"
check_resp "ERR -E2BIG" "string value longer than 1024 bytes"
make_a_run 8192
if printf 'set %s %s big string %s\n' "$MODULE" "$DICT" "$a_run" >&3 2>/dev/null; then
	bad "write longer than 4096 bytes should fail"
else
	ok "write longer than 4096 bytes fails"
fi

echo "-- 7. CAP_MAC_ADMIN enforcement --"
if setpriv --reuid 1000 --regid 1000 --clear-groups sh -c \
     'exec 3<>/sys/kernel/security/lua/shdict' > /dev/null 2>&1; then
	bad "open as uid 1000 should be denied"
else
	ok "open as uid 1000 denied"
fi
# root opens the file, then drops to uid 1000 and writes via the SAME fd:
# the per-op CAP_MAC_ADMIN check must still reject the write with -EPERM.
cat > /tmp/dropwrite.sh <<'EOF'
#!/bin/sh
exec 3<>/sys/kernel/security/lua/shdict
setpriv --reuid 1000 --regid 1000 --clear-groups \
	sh -c 'printf "get demo runtime flag\n" >&3' 2>/dev/null
EOF
chmod +x /tmp/dropwrite.sh
if /tmp/dropwrite.sh > /dev/null 2>&1; then
	bad "write without CAP_MAC_ADMIN on an open fd should fail"
else
	ok "write without CAP_MAC_ADMIN on an open fd fails"
fi

echo "-- 7c. Lua hook reads a NUL-containing string from securityfs --"
# probe_expected is written from userspace as hex "610062" ("a\0b"); the
# hook compares it with the literal Lua string "a\0b" and publishes the
# result under probe_mismatch.
shdict_send set "$MODULE" "$DICT" probe_expected string 610062
check_resp OK "set probe_expected=a<NUL>b"
cat /proc/version > /dev/null
shdict_send get "$MODULE" "$DICT" probe_mismatch
check_resp "bool 0" "Lua hook sees the NUL string unchanged"
shdict_send set "$MODULE" "$DICT" probe_expected string 68656c6c6f
check_resp OK "set probe_expected=hello"
cat /proc/version > /dev/null
shdict_send get "$MODULE" "$DICT" probe_mismatch
check_resp "bool 1" "Lua hook detects a mismatching NUL string"

echo "-- 7d. lightuserdata is never exported to userspace --"
shdict_send get "$MODULE" "$DICT" probe_ptr_found
check_resp "bool 1" "hook harvested the lightuserdata marker"
shdict_send get "$MODULE" "$DICT" probe_ptr_type
check_resp "string 7573657264617461" "marker type is userdata"
shdict_send get "$MODULE" "$DICT" probe_env_n
echo "  (diagnostic: env keys = $resp)"
shdict_send get "$MODULE" "$DICT" ptr
check_resp "ERR -EOPNOTSUPP" "get lightuserdata returns -EOPNOTSUPP"

echo "-- 7e. Lua-side overlong string: get refuses with -E2BIG --"
shdict_send set "$MODULE" "$DICT" probe_long_requested bool 1
check_resp OK "request overlong-string probe"
cat /proc/version > /dev/null   # one dispatch stores the 4096-byte value
shdict_send get "$MODULE" "$DICT" probe_long
check_resp "ERR -E2BIG" "get of 4096-byte string returns -E2BIG"

echo "-- 7f. Lua nil delete recycles node and string --"
# kvcache.nusage from the stats file is the live node count; the delete
# probe allocates two nodes and deletes both, so the count must return to
# the baseline (a leaked node would leave it +2).
kvcache_nusage() {
	sed -n 's/^kvcache.nusage.*= *\([0-9][0-9]*\).*/\1/p' \
		"$BASE/stats" 2>/dev/null | head -n 1
}
before=$(kvcache_nusage)
shdict_send set "$MODULE" "$DICT" probe_del string 01
check_resp OK "set probe_del=01"
shdict_send get "$MODULE" "$DICT" probe_del
check_resp "string 01" "probe_del present before delete"
shdict_send set "$MODULE" "$DICT" probe_del_requested bool 1
check_resp OK "request delete of probe_del"
cat /proc/version > /dev/null   # one dispatch runs the Lua nil delete
shdict_send get "$MODULE" "$DICT" probe_del
check_resp "ERR -ENOENT" "probe_del gone after Lua nil delete"
after=$(kvcache_nusage)
if [ -z "$before" ] || [ -z "$after" ]; then
	ok "delete leak check skipped (CONFIG_SECURITY_LUA_LSM_STATS not built)"
elif [ "$before" = "$after" ]; then
	ok "kvcache node usage back to baseline after delete"
else
	bad "kvcache node usage grew $before -> $after after delete (leak)"
fi

echo "-- 8. non-LIVE module -> -ESHUTDOWN, dict never touched --"
# Pin the module in a task that is permanently running so unregister
# cannot drain it and must leave the module ZOMBIE on the list.
sh -c ': > /dev/null; while :; do :; done' &
spin=$!
sleep 1
if printf '%s\n' "$MODULE" > "$BASE/unregister" 2>/dev/null; then
	bad "unregister should fail with -EBUSY while module is pinned"
else
	ok "unregister failed with -EBUSY while module is pinned"
fi
shdict_send get "$MODULE" "$DICT" flag
check_resp "ERR -ESHUTDOWN" "get on non-LIVE module returns -ESHUTDOWN"
shdict_send set "$MODULE" "$DICT" k bool 1
check_resp "ERR -ESHUTDOWN" "set on non-LIVE module returns -ESHUTDOWN"
kill "$spin" 2>/dev/null
wait "$spin" 2>/dev/null

echo
echo "== summary: PASS=$PASS FAIL=$FAIL =="
exec 3>&-
if [ "$FAIL" -eq 0 ]; then
	echo "LUA-LSM-SHDICT-POC: ALL PASS"
	exit 0
fi
echo "LUA-LSM-SHDICT-POC: FAILURES PRESENT"
exit 1
