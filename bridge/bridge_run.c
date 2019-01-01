#include "bridge.h"
#include "debuglog.h"
#include "vm.h"
#include <errno.h>
#include <linux/kvm.h>
#include <string.h>

void bridge_init_cpu_long(Bridge *br, VCPUSpecialRegs *sregs)
{
    DEBUG_LOG("bridge_init_cpu_long(%p, %p)", br, sregs);

    // Page tables live in Kernel RAM, at some hard-coded addresses
    uint64_t pml4_addr = 0x2000;
    uint64_t *pml4 = (void *)(br->kernel_ram + pml4_addr);
    uint64_t pdpt_addr = 0x3000;
    uint64_t *pdpt = (void *)(br->kernel_ram + pdpt_addr);
    uint64_t pd_addr = 0x4000;
    uint64_t *pd = (void *)(br->kernel_ram + pd_addr);

    // Just one entry in each table for now, since we're keeping things flat and
    // simple.
    pml4[0] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         (uint64_t)GUEST_KERNEL_RAM_START + pdpt_addr);
    pdpt[0] =
        (VCPU_PDE64_PRESENT | // currently in physical memory
         VCPU_PDE64_RW |      // read+write
         VCPU_PDE64_USER |    // accessible from user mode
         (uint64_t)GUEST_KERNEL_RAM_START + pd_addr);
    pd[0] =
        (VCPU_PDE64_PRESENT |           // currently in physical memory
         VCPU_PDE64_RW |                // read+write
         VCPU_PDE64_USER |              // accessible from user mode
         VCPU_PDE64_PS |                // 4MB pages
         (uint64_t)GUEST_MAIN_RAM_START // lives at the beginning of main RAM,
                                        // creating an identity mapping
        );

    // CR3 is the location of Page Map Level 4
    sregs->cr3 = (uint64_t)GUEST_KERNEL_RAM_START + pml4_addr;

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
    regs.rip = 0;

    // For the moment we're creating a hard-coded initial stack at the top
    // of the kernel RAM (which will grow down). We will probably want to do
    // something more interesting here later.
    regs.rsp = (uint64_t)GUEST_KERNEL_RAM_START - (uint64_t)1 +
               (uint64_t)GUEST_KERNEL_RAM_SIZE;

    regs.rip = (uint64_t)GUEST_ROM_START;

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
