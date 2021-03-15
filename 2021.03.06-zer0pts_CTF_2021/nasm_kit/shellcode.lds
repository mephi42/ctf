SECTIONS {
    .shellcode : {
        *(.entry)
        *(.text)
        *(.rodata*)
    }
    /DISCARD/ : { *(*) }
}
