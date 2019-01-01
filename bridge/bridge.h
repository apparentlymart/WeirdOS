#ifndef BRIDGE_H
#define BRIDGE_H

#include "vm.h"

#define KILOBYTE ((size_t)1024)
#define MEGABYTE (KILOBYTE * (size_t)1024)
#define GIGABYTE (MEGABYTE * (size_t)1024)
#define PAGE_TABLE_SIZE ((size_t)4096)

#define GUEST_ROM_START_PHYS ((guestptr_t)0x0000000000000000)
#define GUEST_ROM_START_VIRT ((guestptr_t)0xffffffff80000000)
#define GUEST_ROM_SIZE ((size_t)512 * MEGABYTE)

#define GUEST_KERNEL_RAM_START_PHYS                                            \
    ((guestptr_t)(GUEST_ROM_START_PHYS + GUEST_ROM_SIZE))
#define GUEST_KERNEL_RAM_START_VIRT ((guestptr_t)0xffffffffa0000000)
#define GUEST_KERNEL_RAM_SIZE ((size_t)1536 * MEGABYTE)

#define GUEST_MAIN_RAM_START_PHYS                                              \
    ((guestptr_t)(GUEST_KERNEL_RAM_START_PHYS + GUEST_KERNEL_RAM_SIZE))
#define GUEST_MAIN_RAM_START_VIRT ((guestptr_t)0x0000000000000000)
#define GUEST_MAIN_RAM_SIZE ((size_t)2 * GIGABYTE)

#define GUEST_KERNEL_START_PHYS GUEST_ROM_START_PHYS
#define GUEST_KERNEL_START_VIRT GUEST_ROM_START_VIRT
#define GUEST_KERNEL_SIZE (GUEST_ROM_SIZE + KERNEL_RAM_SIZE)

#define GUEST_KERNEL_STACK_START_VIRT                                          \
    ((guestptr_t)(GUEST_KERNEL_RAM_START_VIRT - 1 + GUEST_KERNEL_RAM_SIZE))
#define GUEST_KERNEL_ENTRY_VIRT GUEST_ROM_START_VIRT
#define GUEST_INIT_PAGE_TABLE_BASE_PHYS GUEST_MAIN_RAM_START_PHYS

typedef struct {
    char *main_ram;
    char *kernel_ram;
    char *kernel_rom;

    KVMMain kvm;
    VM vm;
    VCPU cpus[1];
} Bridge;

const Bridge __victim_bridge;

// BRIDGE_CPU_COUNT is the number of VCPUs per Bridge.
#define BRIDGE_CPU_COUNT                                                       \
    (sizeof(__victim_bridge.cpus) / sizeof(__victim_bridge.cpus[0]))

int bridge_open(Bridge *br, int rom_fd);

int bridge_close(Bridge *br);

// bridge_init_cpus gets the CPUs ready to execute 64-bit code at the start
// of ROM, by configuring page tables and various registers. If this function
// returns successfully, bridge_run can begin execution.
//
// It is not safe to call bridge_init_cpus again after a call to bridge_run,
// since this function does not perform a total reset of the CPU state.
int bridge_init_cpus(Bridge *br);

// bridge_run_cpus spawns a thread for each CPU and blocks until they all
// halt. The CPUs must previously have been initialized with bridge_init_cpus.
int bridge_run_cpus(Bridge *br);

#endif
