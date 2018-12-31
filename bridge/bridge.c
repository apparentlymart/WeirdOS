#include "bridge.h"
#include <errno.h>

const Bridge __victim_bridge;
const int BRIDGE_CPU_COUNT =
    sizeof(__victim_bridge.cpus) / sizeof(__victim_bridge.cpus[0]);

int bridge_init_kvm(Bridge *br)
{
    if (kvm_main_open(&br->kvm) < 0) {
        return -1;
    }

    if (kvm_main_new_vm(&br->kvm, &br->vm) < 0) {
        return -1;
    }

    for (int i = 0; i < BRIDGE_CPU_COUNT; i++) {
        if (vm_new_cpu(&br->vm, &br->cpus[i]) < 0) {
            return -1;
        }
    }
}

int bridge_init_memory(Bridge *br, int rom_fd)
{
    return 0;
}

int bridge_open(Bridge *br, int rom_fd)
{
    if (bridge_init_kvm(br) < 0) {
        goto err;
    }
    if (bridge_init_memory(br, rom_fd) < 0) {
        goto err;
    }
    return 0;

err:
    bridge_close(br);
    return -1;
}

int bridge_close(Bridge *br)
{
    for (int i = 0; i < BRIDGE_CPU_COUNT; i++) {
        if (vcpu_close(&(br->cpus[i])) < 0) {
            return -1;
        }
    }
    if (vm_close(&br->vm) < 0) {
        return -1;
    }
    if (kvm_main_close(&br->kvm)) {
        return -1;
    }

    return 0;
}
