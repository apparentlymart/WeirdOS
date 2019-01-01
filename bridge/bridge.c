#include "bridge.h"
#include "debuglog.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const guestptr_t *GUEST_ROM_START = (void *)0xffffffff80000000;
const size_t GUEST_ROM_SIZE = 512 * 1024 * 1024;
const guestptr_t *GUEST_MAIN_RAM_START = (void *)0x0;
const size_t GUEST_MAIN_RAM_SIZE = (size_t)4096 * (size_t)1024 * (size_t)1024;
const guestptr_t *GUEST_KERNEL_RAM_START = (void *)0xffffffffa0000000;
const size_t GUEST_KERNEL_RAM_SIZE = 1536 * 1024 * 1024;

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
    DEBUG_LOG("bridge_init_memory(%p, %d)", br, rom_fd);

    struct stat statbuf;
    if (fstat(rom_fd, &statbuf) < 0) {
        return -1;
    }

    size_t rom_size = statbuf.st_size;
    if (rom_size != GUEST_ROM_SIZE) {
        DEBUG_LOG(
            "ROM file has size %ld; we expect %ld bytes",
            (long)rom_size,
            (long)GUEST_ROM_SIZE);
        errno = EINVAL;
        return -1;
    }

    DEBUG_LOG("mmap for fd %d of size %ld", rom_fd, (long)rom_size);
    br->kernel_rom = mmap(NULL, rom_size, PROT_READ, MAP_PRIVATE, rom_fd, 0);
    if (br->kernel_rom == MAP_FAILED) {
        DEBUG_LOG("failed to mmap rom_fd: %s", strerror(errno));
        br->kernel_rom = 0;
        return -1;
    }

    if (vm_map_rom(
            &br->vm, 0, br->kernel_rom, rom_size, (guestptr_t)GUEST_ROM_START) <
        0) {
        DEBUG_LOG("failed to map ROM into Guest VM: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int bridge_open(Bridge *br, int rom_fd)
{
    DEBUG_LOG("bridge_open(%p, %d)", br, rom_fd);

    if (bridge_init_kvm(br) < 0) {
        DEBUG_LOG("bridge_init_kvm failed: %s", strerror(errno));
        goto err;
    }
    if (bridge_init_memory(br, rom_fd) < 0) {
        DEBUG_LOG("bridge_init_memory failed: %s", strerror(errno));
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
