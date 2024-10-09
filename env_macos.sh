#!/bin/sh


#brew install coreutils findutils gnu-sed gnu-tar grep llvm make pkg-config


export PATH="$(brew --prefix make)/libexec/gnubin:$PATH"
export PATH="$(brew --prefix llvm)/bin:$PATH"
export PATH="$(brew --prefix lld)/bin:$PATH"


# UUID_T and GETHOSTUUID_H Eliminate compile errors of scripts/mod/file2alias.c
# O_LARGEFILE Eliminate compile errors of usr/gen_init_cpio.c
export HOSTCFLAGS="-D_UUID_T -D__GETHOSTUUID_H -DO_LARGEFILE=0"


# Use gnu sed instead of builtin sed
alias sed='gsed'


# Maybe the symlink is missed on macOS
#ln -s ../../../scripts/syscall.tbl arch/arm64/tools/syscall_64.tbl
#ln -s qcom,sm8550-dispcc.h include/dt-bindings/clock/qcom,sm8650-dispcc.h


#make ARCH=arm64 LLVM=1

#make LLVM=1 menuconfig
#make LLVM=1 -j8
