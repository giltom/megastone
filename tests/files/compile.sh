#!/bin/sh

DIR=$(dirname $0)
mips-linux-gnu-gcc -nostdlib -ffreestanding $DIR/mips_test.S -o $DIR/mips_test.elf