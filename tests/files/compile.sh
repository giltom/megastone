#!/bin/sh

DIR=$(dirname $0)

set -ex

mips-linux-gnu-gcc -nostdlib -ffreestanding $DIR/mips_test.S -o $DIR/mips_test
gcc -Wall -no-pie $DIR/proc_test.c -o $DIR/proc_test