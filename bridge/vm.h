#ifndef VM_H
#define VM_H

#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* CR0 bits */
#define VCPU_CR0_PE 1u
#define VCPU_CR0_MP (1U << 1)
#define VCPU_CR0_EM (1U << 2)
#define VCPU_CR0_TS (1U << 3)
#define VCPU_CR0_ET (1U << 4)
#define VCPU_CR0_NE (1U << 5)
#define VCPU_CR0_WP (1U << 16)
#define VCPU_CR0_AM (1U << 18)
#define VCPU_CR0_NW (1U << 29)
#define VCPU_CR0_CD (1U << 30)
#define VCPU_CR0_PG (1U << 31)

/* CR4 bits */
#define VCPU_CR4_VME 1
#define VCPU_CR4_PVI (1U << 1)
#define VCPU_CR4_TSD (1U << 2)
#define VCPU_CR4_DE (1U << 3)
#define VCPU_CR4_PSE (1U << 4)
#define VCPU_CR4_PAE (1U << 5)
#define VCPU_CR4_MCE (1U << 6)
#define VCPU_CR4_PGE (1U << 7)
#define VCPU_CR4_PCE (1U << 8)
#define VCPU_CR4_OSFXSR (1U << 8)
#define VCPU_CR4_OSXMMEXCPT (1U << 10)
#define VCPU_CR4_UMIP (1U << 11)
#define VCPU_CR4_VMXE (1U << 13)
#define VCPU_CR4_SMXE (1U << 14)
#define VCPU_CR4_FSGSBASE (1U << 16)
#define VCPU_CR4_PCIDE (1U << 17)
#define VCPU_CR4_OSXSAVE (1U << 18)
#define VCPU_CR4_SMEP (1U << 20)
#define VCPU_CR4_SMAP (1U << 21)

#define VCPU_EFER_SCE 1
#define VCPU_EFER_LME (1U << 8)
#define VCPU_EFER_LMA (1U << 10)
#define VCPU_EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define VCPU_PDE32_PRESENT 1
#define VCPU_PDE32_RW (1U << 1)
#define VCPU_PDE32_USER (1U << 2)
#define VCPU_PDE32_PS (1U << 7)

/* 64-bit page entry bits */
#define VCPU_PDE64_PRESENT 1
#define VCPU_PDE64_RW (1U << 1)
#define VCPU_PDE64_USER (1U << 2)
#define VCPU_PDE64_ACCESSED (1U << 5)
#define VCPU_PDE64_DIRTY (1U << 6)
#define VCPU_PDE64_PS (1U << 7)
#define VCPU_PDE64_G (1U << 8)

// If a VM entry failure occurs (KVM_EXIT_FAIL_ENTRY), this bit is set in the
// VMX-specific exit reason, which is distinct from KVM's concept of exit
// reason.
#define VCPU_VMX_EXIT_REASONS_FAILED_VMENTRY (1U << 31)

typedef void *guestptr_t;

typedef struct {
    int fd;
} KVMMain;

typedef struct {
    KVMMain *kvm;
    int fd;
} VM;

typedef struct {
    VM *vm;
    int fd;
    struct kvm_run *kvm_run;
    size_t kvm_run_size;
} VCPU;

typedef struct kvm_regs VCPURegs;
typedef struct kvm_sregs VCPUSpecialRegs;
typedef struct kvm_segment VCPUSegment;

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
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int vm_close(VM *vm);

// vm_map_ram maps a buffer into the VM memory space in read/write mode.
int vm_map_ram(
    VM *vm, u_int32_t slot, char *buf, size_t size, guestptr_t guest_addr);

// vm_map_rom maps a buffer into the VM memory space in read-only mode.
int vm_map_rom(
    VM *vm, u_int32_t slot, char *buf, size_t size, guestptr_t guest_addr);

// vm_new_cpu creates a new VCPU, populating the given VCPU object.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int vm_new_cpu(VM *vm, VCPU *cpu, int64_t id);

// vcpu_close closes the file descriptor associated with the givem VCPU, which
// de-allocates it.
//
// Returns zero on success, or a negative number on failure. If failed, errno
// is set to the error that occurred opening the file.
int vcpu_close(VCPU *cpu);

// vcpu_run starts running the given virtual CPU, returning once it can make
// no further progress without the help of the caller.
int vcpu_run(VCPU *cpu);

// vcpu_get_regs populates the given object with the current register values
// for the given VCPU.
int vcpu_get_regs(VCPU *cpu, VCPURegs *regs);

// vcpu_set_regs writes the given register values to the given VCPU.
int vcpu_set_regs(VCPU *cpu, VCPURegs *regs);

// vcpu_get_special_regs populates the given object with the current special
// register values for the given VCPU.
int vcpu_get_special_regs(VCPU *cpu, VCPUSpecialRegs *sregs);

// vcpu_set_special_regs writes the given special register values to the given
// VCPU.
int vcpu_set_special_regs(VCPU *cpu, VCPUSpecialRegs *regs);

#endif
