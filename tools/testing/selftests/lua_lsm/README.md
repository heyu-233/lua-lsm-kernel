# Lua-LSM shared-dictionary text interface PoC

This PoC exposes the existing Lua shared-dictionary API through
`/sys/kernel/security/lua/shdict`. It does not define a second typed kvcache
API or require a dedicated userspace client.

The end-to-end path is:

```text
userspace text command -> securityfs parser -> Lua call bridge ->
shared.<dict>:set/get/incr -> kvcache -> Lua LSM hook
```

## Request format

Each write contains one line-oriented request of at most 4096 bytes:

```text
set <module> <dict> <key> <boolean|number|string|hex> <value>
get <module> <dict> <key>
delete <module> <dict> <key>
incr <module> <dict> <key> [delta]
```

For normal administration, change to the Lua-LSM securityfs directory and
write readable commands directly:

```sh
cd /sys/kernel/security/lua
echo 'set demo runtime blocked_path string /tmp/blocked' > shdict
cat shdict
grep '^demo runtime blocked_path ' shdict
echo 'delete demo runtime blocked_path' > shdict
```

A fresh read enumerates every key in every named dictionary belonging to a
LIVE module. Each line has this format:

```text
<module> <dict> <key> <type> <escaped-value>
```

Strings use readable text directly. Backslashes and non-printable bytes are
escaped as `\xNN` in enumeration output. The `hex` input type is available for
binary-safe strings such as an embedded NUL:

```sh
echo 'set demo runtime binary_key hex 610062' > shdict
```

Programs that need one exact result can keep the file descriptor open and
read the result of `set`, `get`, `delete`, or `incr` from that same open file.
This keeps request results per-open instead of exposing a racy global
"last-result" slot.

The file mode is `0600`; open and every read/write also require
`CAP_MAC_ADMIN`. The parser never evaluates userspace-provided Lua source.
The bridge constructs a restricted module environment internally and invokes
the existing shared-dictionary methods by using the Lua C API.

## Reproduction

```sh
make -C /home/maomao-wang/work/lua-lsm/kernel \
  O=/home/maomao-wang/work/lua-lsm/out-riscv \
  ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4 Image

/home/maomao-wang/work/lua-lsm/scripts/run-qemu.sh
```

`shdict_poc.sh` verifies:

1. boolean, number, string, embedded-NUL, overwrite, delete, and `incr`
2. dictionary creation on first `shared.<name>` access
3. enumeration across named dictionaries with safe value escaping
4. live updates to `blocked_path` changing a real `file_open` decision
5. malformed commands, unknown modules, unsupported types, and input limits
6. open-time and per-operation `CAP_MAC_ADMIN` enforcement
7. repeated requests without Lua stack contamination
8. rejection of requests after the target module leaves LIVE state

The boot log must contain no unexpected Lua traceback, BUG, WARNING, or
reference-count assertion.

`shdict_stress.sh` additionally runs two writers and two enumeration/hook
readers in parallel, verifies the final atomic counter, and unregisters the
module after all workers exit.

## Implementation boundary

- The string extension remains inside the original kvcache Lua path. String
  payloads are copied, length-aware, immutable, and reference-counted.
- securityfs parses only the public text grammar. It does not directly insert,
  overwrite, or remove kvcache nodes.
- The bridge pushes structured arguments onto the Lua stack and calls the
  original `shared` methods; it does not compile user-supplied Lua code.
- The target module and its dictionaries remain protected for the complete
  call. Every exit path restores the Lua stack and releases all resources.
- The interface remains a development PoC, not a stable userspace ABI.
