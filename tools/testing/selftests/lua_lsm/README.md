# Lua-LSM securityfs shared dict get/set PoC

PoC deliverables for "任务 2": prove the full loop

```
load Lua policy -> hook dispatch creates the shared dict ->
userspace writes/reads it via securityfs -> the Lua hook reads the new
value immediately and the access decision changes
```

All of it is exercised by `shdict_poc.sh` + `shdict_poc.lua` against the
PoC control file `/sys/kernel/security/lua/shdict` (mode 0600, marked
**unstable** — not a formal ABI).

## Reproduction

```sh
# in the linux-dev VM
make -C /home/maomao-wang/work/lua-lsm/kernel \
  O=/home/maomao-wang/work/lua-lsm/out-riscv \
  ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4 Image

# copy shdict_poc.{lua,sh} and run-all.sh into rootfs/initramfs-root/tests/,
# then repack the initramfs:
(cd rootfs/initramfs-root && find . | cpio -o -H newc | gzip > ../rootfs.cpio.gz)

# boot (init runs the selftests and powers off)
/home/maomao-wang/work/lua-lsm/scripts/run-qemu.sh
```

The test registers `shdict_poc.lua` as module `demo`, triggers one real
`file_open` dispatch to create the `runtime` dict, then drives every
command over a single fd. It checks, in order:

1. bool / number / plain string / NUL-containing string round-trips
2. same-key overwrite is visible in the next `get`
3. `blocked_path=/tmp/blocked` denies that path only
4. re-setting `blocked_path` changes hook behavior without a module reload
5. unknown module / dict / key -> `-ENOENT` (both get and set)
6. unknown type, odd-length and non-hex strings, over-limit names and
   values -> `-EINVAL` / `-E2BIG`
7. unprivileged open denied; a root-opened fd must still reject writes
   after dropping to uid 1000 (per-op `CAP_MAC_ADMIN` -> `-EPERM`)
7c. a securityfs-written `"a\0b"` value is compared inside the Lua hook
    against the literal string and stays binary-exact (embedded NULs)
7d. a lightuserdata value stored by the hook (harvested from the module
    env with `getfenv(1)` + `pairs()`) is refused with `-EOPNOTSUPP` and
    never exported to userspace
7e. a Lua-side string whose hex response would overflow the reply buffer
    is refused with `-E2BIG` (no silent truncation)
7f. `shared.runtime.key = nil` from Lua recycles the node: the key is
    gone (`-ENOENT`) and `kvcache.nusage` returns to its baseline (needs
    `CONFIG_SECURITY_LUA_LSM_STATS`; skipped otherwise)
8. a module pinned in a busy task makes `unregister` fail `-EBUSY`; the
   leftover ZOMBIE module answers `-ESHUTDOWN` (get and set) and the
   freed dict is never dereferenced
9. the boot log must show no traceback / BUG / WARNING / refcount KASSERT

## Command / response summary

```
set <module> <dict> <key> bool <0|1>
set <module> <dict> <key> number <signed decimal>
set <module> <dict> <key> string <hex bytes>
get <module> <dict> <key>
      -> OK | bool <0|1> | number <dec> | string <lowercase hex> | ERR -<errno>
```

limits: input <= 4096 bytes; module/dict/key 1..128 bytes, no
whitespace/control chars; decoded string <= 1024 bytes.

## Lifecycle (one page)

- `lua_lsm_module` owns the `shdicts` list (`shdict_lock` +
  `shdict_count`); each `lua_lsm_module_shdict` embeds a `kvcache_dict`
  (rbtree of `kvcache_node`s guarded by the dict's rwlock; per-node
  rwlock + refcount for values and concurrent readers).
- A dict is created **only** by Lua code touching `shared.<name>`
  (`lua_shared_index`), never by securityfs.
- Module states: `COMING -> LIVE -> GOING -> ZOMBIE | freed`.
  `lua_lsm_module_unregister()` moves a module out of LIVE, frees its
  shdicts and GCs its kvnodes all under `modules_mutex`; if some task
  still holds the module it stays listed as ZOMBIE with freed dicts.
- PoC safety boundary (deliberately narrower than upstream PR #16, which
  adds tombstoned refcounted shdict userdata for the Lua side — not
  cherry-picked here): every securityfs lookup (module, then dict under
  `shdict_lock`) and the whole get/set runs with `modules_mutex` held;
  only `LMS_STATE_LIVE` modules are dereferenced. Non-LIVE -> `-ESHUTDOWN`
  before the dict pointer is ever used; unknown module/dict/key -> `-ENOENT`.
- String values are kernel-copied, immutable, refcounted payloads; nodes
  only exchange references, readers hold a reference for the duration of
  a snapshot, and the old value is recycled when the last holder drops it
  (refcount balance holds across insert/overwrite/read/delete/dict free;
  the debug build's refcount KASSERTs catch leaks).
- Known limits: no dict enumeration or delete commands; no per-module
  directories; no `-EBUSY`-then-hook regression test (upstream PR #16's
  territory); same-fd concurrent writers are undefined; empty string
  values are not expressible (token grammar); not stress-tested under
  KASAN/KCSAN.