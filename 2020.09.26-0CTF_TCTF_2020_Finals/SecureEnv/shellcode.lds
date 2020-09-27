SECTIONS {
    .shellcode : {
        *(.text)
        *(.rodata*)
    }
    /DISCARD/ : { *(*) }
}
