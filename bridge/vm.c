
#include "vm.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int kvm_main_open(KVMMain *kvm)
{
    kvm->fd = open("/dev/kvm", O_RDWR);
    if (kvm->fd < 0) {
        kvm->fd = 0;
        return -1;
    }
    return 0;
}

int kvm_main_close(KVMMain *kvm)
{
    if (kvm->fd == 0) {
        return 0;
    }
    int result = close(kvm->fd);
    if (result < 0) {
        return result;
    }
    kvm->fd = 0; // no longer usable
    return 0;
}

int kvm_main_new_vm(KVMMain *kvm, VM *vm)
{
    vm->kvm = kvm;

    vm->fd = ioctl(kvm->fd, KVM_CREATE_VM, 0);
    if (vm->fd < 0) {
        goto err_create;
    }

    if (ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
        goto err_set_tss_addr;
    }

    return 0;

    int orig_err;
err_set_tss_addr:
    orig_err = errno;
    if (close(vm->fd) < 0) {
        errno = orig_err;
        return -1;
    }
    vm->fd = 0;
err_create:
    return -1;
}

int vm_close(VM *vm)
{
    if (vm->fd == 0) {
        return 0;
    }
    int result = close(vm->fd);
    if (result < 0) {
        return result;
    }
    vm->fd = 0; // no longer usable
    return 0;
}

int vm_new_cpu(VM *vm, VCPU *cpu)
{
    cpu->vm = vm;

    cpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
    if (cpu->fd < 0) {
        goto err_create;
    }

    int mmap_size;
    mmap_size = ioctl(vm->kvm->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        goto err_get_mmap_size;
    }

    cpu->kvm_run_size = mmap_size;
    cpu->kvm_run =
        mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu->fd, 0);
    if (cpu->kvm_run == MAP_FAILED) {
        goto err_mmap;
    }

    return 0;

    int orig_err;
err_mmap:
err_get_mmap_size:
    orig_err = errno;
    if (close(cpu->fd) < 0) {
        errno = orig_err;
        return -1;
    }
    cpu->fd = 0;
err_create:
    return -1;
}

int vcpu_close(VCPU *cpu)
{
    if (cpu->fd != 0) {
        if (close(cpu->fd) < 0) {
            return -1;
        }
        cpu->fd = 0; // no longer usable
    }

    if (cpu->kvm_run != NULL) {
        // Also must free our "run" mapping
        if (munmap(cpu->kvm_run, cpu->kvm_run_size) < 0) {
            return -1;
        }
        cpu->kvm_run = NULL;
        cpu->kvm_run_size = 0;
    }

    return 0;
}
