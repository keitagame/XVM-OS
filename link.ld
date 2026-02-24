/* XVM-OS Linker Script */
ENTRY(_start)

SECTIONS {
    . = 0x00100000;

    .multiboot : { *(.multiboot) }
    .text.boot : { *(.text.boot) }
    .text      : { *(.text*) }
    .rodata    : { *(.rodata*) }
    .data      : { *(.data*) }
    .bss       : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /DISCARD/ : { *(.comment) *(.eh_frame*) *(.note*) }
}
