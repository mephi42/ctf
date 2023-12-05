SECTIONS {
    .shellcode : {
        *(.entry)
        *(.text)
        *(.rodata*)
        *(.data)
        *(.bss)
    }
    #/DISCARD/ : { *(*) }
}
