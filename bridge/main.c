
#include "vm.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    KVMMain kvm;
    if (kvm_main_open(&kvm) < 0) {
        perror("kvm_main_open");
        return 1;
    }

    printf("KVM file descriptor %d\n", kvm.fd);

    VM vm;
    if (kvm_main_new_vm(&kvm, &vm) < 0) {
        perror("kvm_main_new_vm");
        return 1;
    }

    printf("VM file descriptor %d\n", vm.fd);

    VCPU cpu;
    if (vm_new_cpu(&vm, &cpu) < 0) {
        perror("vm_new_cpu");
        return 1;
    }

    printf("VCPU file descriptor %d\n", cpu.fd);

    if (vcpu_close(&cpu) < 0) {
        perror("vcpu_close");
        return 1;
    }
    if (vm_close(&vm) < 0) {
        perror("vm_close");
        return 1;
    }
    if (kvm_main_close(&kvm) < 0) {
        perror("kvm_main_close");
        return 1;
    }
    return 0;
}
