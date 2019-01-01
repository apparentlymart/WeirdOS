#ifndef BRIDGE_H
#define BRIDGE_H

#include "vm.h"

#define GUEST_ROM_START ((guestptr_t)0xffffffff80000000)
#define GUEST_ROM_SIZE ((size_t)(512 * 1024 * 1024))
#define GUEST_MAIN_RAM_START ((guestptr_t)0x0000000000000000)
#define GUEST_MAIN_RAM_SIZE ((size_t)2048 * (size_t)1024 * (size_t)1024)
#define GUEST_KERNEL_RAM_START ((guestptr_t)0xffffffffa0000000)
#define GUEST_KERNEL_RAM_SIZE ((size_t)(1536 * 1024 * 1024) - (size_t)0x2000)
// GUEST_KERNEL_RAM_SIZE leaves one page unused at the end of the memory space
// because otherwise a check in the kernel fails: START + SIZE is zero, which
// the kernel considers to be an error because it is less than START.

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
