SECTIONS {
    .shellcode : {
        *(.text.shellcode)
        patch_start = .;
        *(.text.patch)
        patch_end = .;
        *(.rodata*)
    }
    /DISCARD/ : { *(*) }
}
