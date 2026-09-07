#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Lua-LSM shared-dictionary Lua execution PoC.
# Request format: first line is the module name, remaining bytes are Lua.

set -u

BASE=/sys/kernel/security/lua
SHDICT=$BASE/shdict
POLICY=${1:-$(dirname -- "$0")/shdict_poc.lua}
MODULE=demo
PASS=0
FAIL=0
RESP_FILE=/tmp/shdict-response

ok()  { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# Write one request and read its raw result from the same open file.
lua_send() {
	module=$1
	code=$2
	if ! printf '%s\n%s\n' "$module" "$code" >&3 2>/dev/null; then
		resp=
		return 1
	fi
	resp=$(cat <&3)
	return 0
}

lua_send_file() {
	module=$1
	code=$2
	if ! printf '%s\n%s\n' "$module" "$code" >&3 2>/dev/null; then
		: > "$RESP_FILE"
		return 1
	fi
	cat <&3 > "$RESP_FILE"
}

lua_expect() {
	expected=$1
	code=$2
	description=$3
	if lua_send "$MODULE" "$code" && [ "$resp" = "$expected" ]; then
		ok "$description"
	else
		bad "$description (expected '$expected', got '$resp')"
	fi
}

lua_must_fail() {
	module=$1
	code=$2
	description=$3
	if lua_send "$module" "$code"; then
		bad "$description (request unexpectedly succeeded)"
	else
		ok "$description"
	fi
}

make_a_run() {
	a_run=a
	while [ ${#a_run} -lt "$1" ]; do
		a_run=$a_run$a_run
	done
}

echo "== Lua-LSM shared dictionary Lua interface PoC =="
[ -f "$POLICY" ] || { bad "policy $POLICY not found"; exit 1; }
[ -w "$SHDICT" ] || { bad "$SHDICT missing"; exit 1; }

cat "$POLICY" > "$BASE/register" || { bad "module register failed"; exit 1; }
ok "module registered"
exec 3<>"$SHDICT" || { bad "cannot open $SHDICT"; exit 1; }

echo "-- 1. direct Lua set/get and on-demand dictionary creation --"
lua_expect true 'return shared.runtime:set("flag", true)' "set bool through Lua API"
lua_expect true 'return shared.runtime:get("flag")' "get bool through Lua API"
lua_expect true 'return shared.runtime:set("number", 42)' "set number through Lua API"
lua_expect 42 'return shared.runtime:get("number")' "get number through Lua API"
lua_expect true 'return shared.runtime:set("message", "hello world")' "set plain string"
lua_expect "hello world" 'return shared.runtime:get("message")' "get plain string"
lua_expect 2 'return shared.runtime:incr("counter", 2)' "incr creates a counter"
lua_expect 3 'return shared.runtime:incr("counter")' "incr updates a counter"

echo "-- 2. binary-safe strings, overwrite and delete --"
lua_expect true 'return shared.runtime:set("probe_expected", "a\0b")' "set embedded-NUL string"
if lua_send_file "$MODULE" 'return shared.runtime:get("probe_expected")'; then
	hex=$(od -An -tx1 "$RESP_FILE" | tr -d ' \n')
	[ "$hex" = 610062 ] && ok "embedded-NUL string returned intact" || \
		bad "embedded-NUL result (expected 610062, got $hex)"
else
	bad "get embedded-NUL string"
fi
lua_expect true 'return shared.runtime:set("message", "new")' "overwrite string"
lua_expect new 'return shared.runtime:get("message")' "overwritten value visible"
lua_expect true 'return shared.runtime:set("message", nil)' "delete with nil"
lua_expect true 'return shared.runtime:get("message") == nil' "deleted key is absent"

echo "-- 3. restricted execution environment --"
lua_expect true 'return current == nil' "current is not exposed"
lua_expect true 'return require == nil' "require is not exposed"
lua_expect true 'return _G == nil' "global environment is not exposed"

echo "-- 4. dynamic file-access decision --"
touch /tmp/blocked /tmp/blocked2 /tmp/plain || { bad "touch fixtures"; exit 1; }
lua_expect true 'return shared.runtime:set("blocked_path", "/tmp/blocked")' \
	"configure /tmp/blocked"
if cat /tmp/blocked > /dev/null 2>&1; then
	bad "open /tmp/blocked should be denied"
else
	ok "open /tmp/blocked denied"
fi
cat /tmp/plain > /dev/null 2>&1 && ok "unmatched path allowed" || \
	bad "unmatched path should be allowed"
lua_expect true 'return shared.runtime:set("blocked_path", "/tmp/blocked2")' \
	"update policy without reload"
cat /tmp/blocked > /dev/null 2>&1 && ok "old path allowed after update" || \
	bad "old path should be allowed after update"
if cat /tmp/blocked2 > /dev/null 2>&1; then
	bad "new path should be denied"
else
	ok "new path denied after update"
fi

echo "-- 5. Lua result and error boundaries --"
cat /proc/version > /dev/null
lua_expect false 'return shared.runtime:get("probe_mismatch")' \
	"hook reads embedded-NUL value consistently"
lua_must_fail "$MODULE" 'return shared.runtime:get("ptr")' \
	"lightuserdata result is refused"
lua_must_fail nosuch 'return shared.runtime:get("flag")' "unknown module is refused"
lua_must_fail "$MODULE" 'return shared.runtime:get(' "syntax error is refused"
lua_must_fail "$MODULE" 'return shared.runtime:no_such_method()' \
	"runtime error is refused"
lua_must_fail "$MODULE" 'return {}' "non-scalar result is refused"
lua_expect true 'return shared.runtime:set("probe_long_requested", true)' \
	"request an overlong Lua result"
cat /proc/version > /dev/null
lua_must_fail "$MODULE" 'return shared.runtime:get("probe_long")' \
	"result over 4096 bytes is refused"

make_a_run 256
lua_must_fail "$a_run" 'return true' "module name over 128 bytes is refused"
if printf '%s' "$MODULE" >&3 2>/dev/null; then
	bad "request without module separator should fail"
else
	ok "request without module separator fails"
fi
if printf '%s\n' "$MODULE" >&3 2>/dev/null; then
	bad "request without Lua code should fail"
else
	ok "request without Lua code fails"
fi
make_a_run 8192
if printf '%s\nreturn "%s"\n' "$MODULE" "$a_run" >&3 2>/dev/null; then
	bad "request over 4096 bytes should fail"
else
	ok "request over 4096 bytes fails"
fi

echo "-- 6. permission checks --"
if setpriv --reuid 1000 --regid 1000 --clear-groups sh -c \
	'exec 4<>/sys/kernel/security/lua/shdict' > /dev/null 2>&1; then
	bad "unprivileged open should fail"
else
	ok "unprivileged open denied"
fi
if setpriv --reuid 1000 --regid 1000 --clear-groups sh -c \
	'printf "demo\nreturn true\n" >&3' 2>/dev/null; then
	bad "unprivileged write on inherited fd should fail"
else
	ok "per-operation capability check enforced"
fi

echo "-- 7. repeated execution and Lua stack cleanup --"
i=1
repeat_ok=1
while [ "$i" -le 100 ]; do
	if ! lua_send "$MODULE" "return shared.runtime:set(\"repeat\", $i)" || \
	   [ "$resp" != true ]; then
		repeat_ok=0
		break
	fi
	i=$((i + 1))
done
[ "$repeat_ok" -eq 1 ] && ok "100 repeated Lua requests" || \
	bad "repeated Lua request $i"
lua_expect 100 'return shared.runtime:get("repeat")' "stack remains usable"

echo "-- 8. module lifecycle boundary --"
sh -c ': > /dev/null; while :; do :; done' &
spin=$!
sleep 1
if printf '%s\n' "$MODULE" > "$BASE/unregister" 2>/dev/null; then
	bad "unregister should fail while module is pinned"
else
	ok "busy unregister refused"
fi
lua_must_fail "$MODULE" 'return shared.runtime:get("flag")' \
	"non-LIVE module is refused"
kill "$spin" 2>/dev/null
wait "$spin" 2>/dev/null

echo
echo "== summary: PASS=$PASS FAIL=$FAIL =="
exec 3>&-
rm -f "$RESP_FILE"
if [ "$FAIL" -eq 0 ]; then
	echo "LUA-LSM-SHDICT-POC: ALL PASS"
	exit 0
fi
echo "LUA-LSM-SHDICT-POC: FAILURES PRESENT"
exit 1
