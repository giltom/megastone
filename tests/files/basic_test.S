.section .text

.global _start
_start:
.global __start
__start:
    nop


.section .data
.global magic
magic:
    .int 0xDEADBEEF