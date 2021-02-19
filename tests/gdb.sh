#!/bin/sh

gdb-multiarch -ex "set disassembly-flavor intel" -ex "target remote localhost:1234" -ex "x/20i \$pc" -ex "set disassemble-next-line on" 