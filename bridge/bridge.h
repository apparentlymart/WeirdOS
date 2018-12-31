#ifndef BRIDGE_H
#define BRIDGE_H

#include "vm.h"

typedef struct {
    char *main_ram;
    char *kernel_ram;
    char *kernel_rom;

    KVMMain kvm;
    VM vm;
    VCPU cpus[1];
} Bridge;

int bridge_open(Bridge *br, int rom_fd);

int bridge_close(Bridge *br);

#endif
