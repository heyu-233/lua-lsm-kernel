# Lua-LSM shared-dictionary Lua interface PoC

This PoC exposes the existing Lua shared-dictionary API through
`/sys/kernel/security/lua/shdict`. It does not define a second typed C API
or require a dedicated userspace client.

The end-to-end path is:

```
userspace Lua request -> securityfs -> restricted module environment ->
shared.<dict>:set/get/incr -> kvcache -> Lua LSM hook
```

## Request format

Each write contains a module name on the first line and one Lua chunk in the
remaining bytes:

```text
demo
return shared.runtime:set("blocked_path", "/tmp/blocked")
```

```text
demo
return shared.runtime:get("blocked_path")
```

Open the file once when a result is needed, because the result is read back
from the same file description:

```sh
exec 3<>/sys/kernel/security/lua/shdict
printf '%s\n%s\n' demo \
  'return shared.runtime:set("blocked_path", "/tmp/blocked")' >&3
cat <&3

printf '%s\n%s\n' demo \
  'return shared.runtime:get("blocked_path")' >&3
cat <&3
```

The execution environment exposes only `shared` for the selected module.
It does not expose `current`, `require`, `_G`, or the policy module
table. Access to the file requires `CAP_MAC_ADMIN` and its mode is `0600`.

Successful scalar results are returned without type tags:

- `nil`: empty result
- boolean: `true` or `false`
- number: Lua's decimal representation
- string: exact raw bytes, including embedded NULs

Other result types fail with `-EOPNOTSUPP`. Invalid framing, syntax errors,
runtime errors, unknown modules, non-LIVE modules, and oversized requests are
reported through the failing `write(2)`.

## Reproduction

```sh
# Build in the linux-dev VM
make -C /home/maomao-wang/work/lua-lsm/kernel \
  O=/home/maomao-wang/work/lua-lsm/out-riscv \
  ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4 Image

# Copy shdict_poc.{lua,sh} and run-all.sh into the initramfs tests directory,
# repack the initramfs, and boot the automated QEMU runner.
/home/maomao-wang/work/lua-lsm/scripts/run-qemu.sh
```

`shdict_poc.sh` verifies:

1. bool, number, string, embedded-NUL, overwrite, delete, and `incr`
2. dictionary creation on first `shared.<name>` access
3. the restricted execution environment
4. live updates to `blocked_path` changing a real `file_open` decision
5. unknown modules, Lua errors, unsupported results, and input limits
6. open-time and per-operation `CAP_MAC_ADMIN` enforcement
7. repeated requests without Lua stack contamination
8. rejection of requests after the target module leaves LIVE state

The boot log must contain no Lua traceback outside intentional negative tests,
BUG, WARNING, or reference-count assertion.

## Implementation boundary

- The string extension remains inside the original kvcache Lua path. String
  payloads are copied, length-aware, immutable, and reference-counted.
- securityfs parses only the module-name framing; Lua parses and executes the
  dictionary operation.
- The target module and its dictionaries remain protected for the complete Lua
  call. `lvm_get()` runs before the module lifecycle lock and every exit path
  restores the Lua stack and releases both resources.
- The interface is a development PoC, not a stable userspace ABI.
