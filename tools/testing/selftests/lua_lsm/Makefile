# SPDX-License-Identifier: GPL-2.0
#
# Lua-LSM securityfs shared dict PoC selftest.
#
# The shell test drives /sys/kernel/security/lua/shdict and needs a kernel
# with CONFIG_SECURITY_LUA_LSM plus securityfs mounted; it is meant to run
# in the lua-lsm QEMU development initramfs (see README.md for the repro
# instructions).

TEST_PROGS := shdict_poc.sh shdict_stress.sh
TEST_FILES := shdict_poc.lua shdict_stress.lua

include ../lib.mk
