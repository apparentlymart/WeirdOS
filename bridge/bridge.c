#include "bridge.h"
#include "debuglog.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
    br->kernel_rom =
        mmap(NULL, rom_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, rom_fd, 0);
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

    DEBUG_LOG(
        "kernel RAM anonymous mmap of size %ld", (long)GUEST_KERNEL_RAM_SIZE);
    br->kernel_ram = mmap(
        NULL,
        GUEST_KERNEL_RAM_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    if (br->kernel_ram == MAP_FAILED) {
        DEBUG_LOG("failed to mmap kernel RAM: %s", strerror(errno));
        br->kernel_ram = 0;
        return -1;
    }

    if (vm_map_ram(
            &br->vm,
            1,
            br->kernel_ram,
            GUEST_KERNEL_RAM_SIZE,
            (guestptr_t)GUEST_KERNEL_RAM_START) < 0) {
        DEBUG_LOG(
            "failed to map kernel RAM into Guest VM: %s", strerror(errno));
        return -1;
    }

    DEBUG_LOG("main RAM anonymous mmap of size %ld", (long)GUEST_MAIN_RAM_SIZE);
    br->main_ram = mmap(
        NULL,
        GUEST_MAIN_RAM_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    if (br->main_ram == MAP_FAILED) {
        DEBUG_LOG("failed to mmap main RAM: %s", strerror(errno));
        br->main_ram = 0;
        return -1;
    }

    if (vm_map_ram(
            &br->vm,
            2,
            br->main_ram,
            GUEST_MAIN_RAM_SIZE,
            (guestptr_t)GUEST_MAIN_RAM_START) < 0) {
        DEBUG_LOG("failed to map main RAM into Guest VM: %s", strerror(errno));
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
