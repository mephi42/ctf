SECTIONS {
    .shellcode : {
        *(.entry)
        *(.text*)
        *(.rodata*)
        *(.data*)
        *(.bss)
        _end = .;
    }
}
