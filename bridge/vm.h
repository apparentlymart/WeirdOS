#ifndef VM_H
#define VM_H

#include <stddef.h>

typedef struct {
    int fd;
} KVMMain;

typedef struct {
    KVMMain *kvm;
    int fd;
    char *main_ram;
    char *kernel_ram;
    char *kernel_rom;
} VM;

typedef struct {
    VM *vm;
    int fd;
    struct kvm_run *kvm_run;
    size_t kvm_run_size;
} VCPU;

// kvm_main_open opens the main KVM API (/dev/kvm) to initialize a kvm_main
// object.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int kvm_main_open(KVMMain *kvm);

// kvm_main_close closes the file descriptor associated with the given KVMMain,
// rendering it unusable.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int kvm_main_close(KVMMain *kvm);

// kvm_main_new_vm creates a new VM, populating the given VM object.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int kvm_main_new_vm(KVMMain *kvm, VM *vm);

// vm_close closes the file descriptor associated with the givem VM, which
// de-allocates it.
//
// This function does NOT free the main_ram, kernel_ram, or kernel_rom. These
// must be freed by the caller after this function returns successfully.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int vm_close(VM *vm);

// vm_new_cpu creates a new VCPU, populating the given VCPU object.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int vm_new_cpu(VM *vm, VCPU *cpu);

// vcpu_close closes the file descriptor associated with the givem VCPU, which
// de-allocates it.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int vcpu_close(VCPU *cpu);

#endif
