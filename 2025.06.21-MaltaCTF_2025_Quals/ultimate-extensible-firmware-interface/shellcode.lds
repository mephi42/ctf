SECTIONS {
    .shellcode : {
        __ImageBase = .;
        *(.entry)
    }
}
