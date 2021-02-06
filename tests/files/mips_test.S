.section .text

.global __start
__start:
    add $t0, $t1, $t2
    nop

.section .data
.global start_data
start_data:
    .int 0xDEADBEEF

.section .bss
    .space 0x1000