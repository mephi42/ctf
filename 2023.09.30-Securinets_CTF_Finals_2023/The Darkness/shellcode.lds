SECTIONS {
    .shellcode : {
    shellcode_start = .;
        *(.entry)
        *(.text)
        *(.rodata*)
        *(.bss)
    shellcode_end = .;
    }
    /DISCARD/ : { *(*) }
}
