#include "bridge.h"
#include "debuglog.h"
#include "vm.h"
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <string.h>

typedef uint64_t _pagetable_t[512];

void bridge_init_cpu_long(Bridge *br, VCPUSpecialRegs *sregs)
{
    DEBUG_LOG("bridge_init_cpu_long(%p, %p)", br, sregs);

    // Our initial page tables live at the bottom of main RAM. The kernel will
    // probably construct its own tables somewhere else and then discard these
    // once it is up and running.
    // In our initial memory map is built from 1GB pages, with the following
    // structure:
    // 000000000 000000000 - Main RAM first GB
    // 000000000 000000001 - Main RAM second GB
    // 111111111 111111110 - Kernel ROM (512MB) followed by initial Kernel RAM
    // 111111111 111111111 - The rest of Kernel RAM
    //
    // Since the kernel RAM and main RAM are contiguous in physical memory,
    // the guest kernel may choose to ignore that distinction once it is up
    // and running, but the separate kernel RAM gives us a place to put the
    // kernel stack and static variables during boot.

    _pagetable_t *tables = (_pagetable_t *)br->main_ram;

    // The first table is PML4, our entry point. This has only two entries:
    // all zeroes (main space) or all ones (kernel space).
    tables[0][0b000000000] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         (uint64_t)GUEST_INIT_PAGE_TABLE_BASE_PHYS + PAGE_TABLE_SIZE);
    tables[0][0b111111111] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         (uint64_t)GUEST_INIT_PAGE_TABLE_BASE_PHYS + PAGE_TABLE_SIZE * 2);

    // Tables 1 and 2 are our two level 3 tables (PDPT), each of which also
    // has two entries, each describing a single 1GB page. Since we're using
    // huge pages, these refer directly to final memory locations and we don't
    // use the other levels here.
    tables[1][0b000000000] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         VCPU_PDE64_PS |      // Large (1GB) page
         (uint64_t)GUEST_MAIN_RAM_START_PHYS);
    tables[1][0b000000001] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         VCPU_PDE64_PS |      // Large (1GB) page
         (uint64_t)GUEST_MAIN_RAM_START_PHYS + GIGABYTE);
    tables[2][0b111111110] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         VCPU_PDE64_PS |      // Large (1GB) page
         (uint64_t)GUEST_KERNEL_START_PHYS);
    tables[2][0b111111111] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         VCPU_PDE64_PS |      // Large (1GB) page
         (uint64_t)GUEST_KERNEL_START_PHYS + GIGABYTE);

    // CR3 is the location of Page Map Level 4
    sregs->cr3 = (uint64_t)GUEST_INIT_PAGE_TABLE_BASE_PHYS;

    // CR4 is a protected mode flag register.
    sregs->cr4 = VCPU_CR4_PAE; // Physical address extension

    // CR0 is a general flag register.
    // Several of these flags are meaningless in long mode but we must set
    // them because a real OS moving from real mode to protected more to
    // long mode would've needed to set these on its journey.
    sregs->cr0 =
        (VCPU_CR0_PE | // protected mode is enabled
         VCPU_CR0_MP | // monitor multi-processor
         VCPU_CR0_ET | // math coprocessor type
         VCPU_CR0_NE | // internal x87 floating point error reporting
         VCPU_CR0_WP | // write protect
         VCPU_CR0_AM | // alignment checking
         VCPU_CR0_PG   // paging is enabled
        );

    // Extended Feature Enable Register
    sregs->efer =
        (VCPU_EFER_LME | // Long mode enabled
         VCPU_EFER_LMA   // Long mode active
        );

    // Selectors are not used in the conventional way in long mode, instead
    // just serving as a location for some flags and other state, and so
    // we'll just put a flat mapping in all of them to start and the kernel
    // will fiddle with the details as needed once it's running.
    VCPUSegment seg = {
        .base = 0,
        .limit = 0xffffffff, // Ignored in long mode
        .selector = 1 << 3,
        .present = 1,
        .type = 11, // execute, read, accessed
        .dpl = 0,
        .db = 0,
        .s = 1, // code/data
        .l = 1,
        .g = 1, // 4KB granularity
    };
    sregs->cs = seg; // the whole struct contents are copied here

    // Since cs took a copy, we can now safely mutate it to deal with the
    // few differences for all of the other selectors.
    seg.type = 3; // read/write, accessed
    seg.selector = 2 << 3;
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

int bridge_init_cpu(Bridge *br, int idx, VCPU *cpu)
{
    DEBUG_LOG("bridge_init_cpu(%p, %d, %p)", br, idx, cpu);

    VCPURegs regs;
    VCPUSpecialRegs sregs;

    if (vcpu_get_regs(cpu, &regs) < 0) {
        DEBUG_LOG("vcpu_get_regs failed for VCPU %d: %s", idx, strerror(errno));
        return -1;
    }

    if (vcpu_get_special_regs(cpu, &sregs) < 0) {
        DEBUG_LOG(
            "vcpu_get_special_regs failed for VCPU %d: %s",
            idx,
            strerror(errno));
        return -1;
    }

    bridge_init_cpu_long(br, &sregs);

    regs.rflags = 2;
    regs.rsp = (uint64_t)GUEST_KERNEL_STACK_START_VIRT; // Initial stack pointer
    regs.rip = (uint64_t)GUEST_KERNEL_ENTRY_VIRT; // Initial instruction pointer

    if (vcpu_set_regs(cpu, &regs) < 0) {
        DEBUG_LOG("vcpu_set_regs failed for VCPU %d: %s", idx, strerror(errno));
        return -1;
    }

    if (vcpu_set_special_regs(cpu, &sregs) < 0) {
        DEBUG_LOG(
            "vcpu_set_sregs failed for VCPU %d: %s", idx, strerror(errno));
        return -1;
    }

    return 0;
}

int bridge_init_cpus(Bridge *br)
{
    DEBUG_LOG("bridge_init_cpus(%p)", br);
    for (int i = 0; i < BRIDGE_CPU_COUNT; i++) {
        if (bridge_init_cpu(br, i, &br->cpus[i]) < 0) {
            DEBUG_LOG("Failed to initialize CPU %d: %s", i, strerror(errno));
            return -1;
        }
    }
    return 0;
}

struct vcpu_run_args {
    Bridge *br;
    int index;
    VCPU *cpu;
};

void *bridge_run_cpu(void *args_raw)
{
    struct vcpu_run_args *args = (struct vcpu_run_args *)args_raw;
    DEBUG_LOG(
        "bridge_run_cpu for CPU %d on VCPU %p (fd %d)",
        args->index,
        args->cpu,
        args->cpu->fd);

    VCPU *cpu = args->cpu;
    VCPURegs regs;

    int bad_exit = 0;

    for (;;) {
        if (vcpu_run(cpu) < 0) {
            DEBUG_LOG(
                "Failed to run VCPU %d: %s", args->index, strerror(errno));
            break;
        }

        switch (cpu->kvm_run->exit_reason) {
        case KVM_EXIT_HLT:
            goto done;

        case KVM_EXIT_IO:
            if (cpu->kvm_run->io.direction == KVM_EXIT_IO_OUT &&
                cpu->kvm_run->io.port == 0xE9) {
                char *p = (char *)cpu->kvm_run;
                DEBUG_LOG(
                    "VCPU %d generates console output: %.*s",
                    args->index,
                    cpu->kvm_run->io.size,
                    p + cpu->kvm_run->io.data_offset);
            } else {
                switch (cpu->kvm_run->io.direction) {
                case KVM_EXIT_IO_OUT:
                    DEBUG_LOG(
                        "VCPU %d unsupported IO out to port %x",
                        args->index,
                        (int)cpu->kvm_run->io.port);
                case KVM_EXIT_IO_IN:
                    DEBUG_LOG(
                        "VCPU %d unsupported IO in from port %x",
                        args->index,
                        (int)cpu->kvm_run->io.port);
                default:
                    DEBUG_LOG(
                        "VCPU %d unsupported IO operation on port %x",
                        args->index,
                        (int)cpu->kvm_run->io.port);
                }
            }
            break;

        case KVM_EXIT_SHUTDOWN:
            // For the x86_64 architecture, this reason indicates a triple
            // fault.
            DEBUG_LOG("VCPU %d failed with a triple fault", args->index);
            bad_exit = 1;
            goto done;

        case KVM_EXIT_INTERNAL_ERROR:
            DEBUG_LOG("VCPU %d encountered a KVM internal error", args->index);
            bad_exit = 1;
            goto done;

        case KVM_EXIT_FAIL_ENTRY:
            0;
            uint64_t code =
                cpu->kvm_run->fail_entry.hardware_entry_failure_reason;

            DEBUG_LOG(
                "VCPU %d produced KVM_EXIT_FAIL_ENTRY with "
                "arch-specific code "
                "0x%lxd",
                args->index,
                (unsigned long)code);
            bad_exit = 1;
            goto done;

        default:
            DEBUG_LOG(
                "VCPU %d gave unrecognized exit reason %d",
                args->index,
                cpu->kvm_run->exit_reason);
            goto done;
        }
    }

done:

    if (bad_exit) {
        // If we're exiting in a bad way then we'll try to emit some diagnostic
        // information.
        VCPUSpecialRegs sregs;

        if (vcpu_get_regs(cpu, &regs) >= 0) {
            DEBUG_LOG(
                "VCPU %d register values:\n    rax: %016lx    "
                "rbx: %016lx\n    rcx: %016lx    rdx: %016lx\n    rbp: %016lx  "
                "  rsp: %016lx\n    rsi: %016lx    rdi: %016lx\n     r8: "
                "%016lx     r9: %016lx\n    rip: %016lx",
                args->index,
                (unsigned long)regs.rax,
                (unsigned long)regs.rbx,
                (unsigned long)regs.rcx,
                (unsigned long)regs.rdx,
                (unsigned long)regs.rbp,
                (unsigned long)regs.rsp,
                (unsigned long)regs.rsi,
                (unsigned long)regs.rdi,
                (unsigned long)regs.r8,
                (unsigned long)regs.r9,
                (unsigned long)regs.rip);
        } else {
            DEBUG_LOG(
                "Failed to get registers for VCPU %d: %s",
                args->index,
                strerror(errno));
        }
        if (vcpu_get_special_regs(cpu, &sregs) >= 0) {
            DEBUG_LOG(
                "VCPU %d special register values:\n    cr0: %016lx    cr2: "
                "%016lx\n    cr3: %016lx    cr4: %016lx\n   efer: %016lx",
                args->index,
                (unsigned long)sregs.cr0,
                (unsigned long)sregs.cr2,
                (unsigned long)sregs.cr3,
                (unsigned long)sregs.cr4,
                (unsigned long)sregs.efer);
        } else {
            DEBUG_LOG(
                "Failed to get special registers for VCPU %d: %s",
                args->index,
                strerror(errno));
        }
    }

    DEBUG_LOG("VCPU %d is terminating", args->index);
    return NULL;
}

int bridge_run_cpus(Bridge *br)
{
    DEBUG_LOG("bridge_run_cpus(%p)", br);

    pthread_t threads[BRIDGE_CPU_COUNT];
    struct vcpu_run_args args[BRIDGE_CPU_COUNT];

    for (int i = 0; i < BRIDGE_CPU_COUNT; i++) {
        DEBUG_LOG("creating run thread for VCPU %d", i);
        args[i].br = br;
        args[i].index = i;
        args[i].cpu = &br->cpus[i];
        int result =
            pthread_create(&threads[i], NULL, bridge_run_cpu, &args[i]);
        if (result != 0) {
            DEBUG_LOG(
                "pthread_create for VCPU %d failed: %s", i, strerror(result));
            args[i].br ==
                NULL; // indicates failed thread for our join loop below
        }
    }

    DEBUG_LOG(
        "waiting for %ld VCPU thread(s) to terminate", (long)BRIDGE_CPU_COUNT);
    for (int i = 0; i < BRIDGE_CPU_COUNT; i++) {
        if (args[i].br == NULL) {
            continue; // indicates that pthread_create failed above
        }
        int result = pthread_join(threads[i], NULL);
        if (result != 0) {
            DEBUG_LOG(
                "pthread_join for VCPU %d failed: %s", i, strerror(result));
            threads[i] == 0;
        }
    }
    DEBUG_LOG("all %ld VCPU thread(s) have exited", (long)BRIDGE_CPU_COUNT);

    return 0;
}
