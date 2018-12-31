OUTPUT_FORMAT(elf64-x86-64)

MEMORY {
    kernel_rom : org = 0xffffffff80000000, len = 512M
    kernel_ram : org = 0xffffffffa0000000, len = 1536M
}

SECTIONS {
    . = 0;
    .start : {
        KERNEL_ENTRY = .;
        *(.start)
    } >kernel_rom
    .text : {
        *(.text*)
        . = ALIGN(4096);
    } >kernel_rom
    .rodata : {
        *(.rodata)
        . = ALIGN(4096);
    } >kernel_rom
    .data : {
        DATA_LOAD_START = LOADADDR(.data);
        DATA_VIRT_START = .;
        *(.data)
        DATA_VIRT_END = .;
    } >kernel_ram AT>kernel_rom
    .bss : {
        BSS_VIRT_START = .;
        *(.bss)
        *(COMMON)
        BSS_VIRT_END = .;
        . = ALIGN(4096);
    } >kernel_ram AT>kernel_rom

    _end = .;

   /DISCARD/ : {
        *(.comment)
   }
}
