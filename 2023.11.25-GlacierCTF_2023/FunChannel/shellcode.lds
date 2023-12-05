SECTIONS {
    .shellcode : {
        *(.entry)
        *(.rodata*)
        shellcode_end = .;
    }
    /DISCARD/ : { *(*) }
}
