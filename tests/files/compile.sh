#!/bin/bash

DIR=$(dirname $0)

function compile_basic  {
    $2 -Wall -no-pie -ffreestanding -nostdlib $DIR/basic_test.S -o $DIR/elfs/$1
}

set -ex

mips-linux-gnu-gcc -nostdlib -ffreestanding $DIR/mips_test.S -o $DIR/mips_test
gcc -Wall -no-pie $DIR/proc_test.c -o $DIR/proc_test


compile_basic "x86-64"    "x86_64-linux-gnu-gcc"
compile_basic "x86"       "x86_64-linux-gnu-gcc -m32"
compile_basic "arm"       "arm-linux-gnueabi-gcc"
compile_basic "armbe"     "arm-linux-gnueabi-gcc -mbig-endian"
compile_basic "arm64"     "aarch64-linux-gnu-gcc"
compile_basic "mips"      "mips-linux-gnu-gcc"
compile_basic "mipsle"    "mipsel-linux-gnu-gcc"
compile_basic "mips64"    "mips64-linux-gnuabi64-gcc"
compile_basic "mips64le"  "mips64el-linux-gnuabi64-gcc"
compile_basic "ppc"       "powerpc-linux-gnu-gcc"