#include <stddef.h>
#include <stdint.h>

#define SYSCALL_COMPLETE (~(uint64_t)0)

extern char DATA_LOAD_START;
extern char DATA_VIRT_START;
extern char DATA_VIRT_END;
extern char BSS_VIRT_START;
extern char BSS_VIRT_END;

struct _syscall_dev_msg {
    uint64_t callnum;
    uint64_t params[6]; // Unused params should be left set to zero.
    uint64_t result;
};

// The syscall device's messaging area is 1GB into main RAM, which is 1GB
// from zero in our initial virtual address space.
volatile struct _syscall_dev_msg *syscall_msgs =
    (struct _syscall_dev_msg *)(1024 * 1024 * 1024);

static inline void outb(uint16_t port, uint8_t value)
{
    asm("outb %0,%1" : /* empty */ : "a"(value), "Nd"(port) : "memory");
}

static inline void cpuid(int code, uint32_t *a, uint32_t *d)
{
    asm volatile("cpuid" : "=a"(*a), "=d"(*d) : "a"(code) : "ecx", "ebx");
}

static inline void sfence()
{
    asm volatile("sfence");
}

volatile int disable_int_count;

static inline void disable_int(uint16_t port, uint8_t value)
{
    asm("cli");
    disable_int_count++;
}

static inline void enable_int(uint16_t port, uint8_t value)
{
    disable_int_count--;
    if (disable_int_count <= 1) {
        asm("sti");
    }
}

static inline void start_syscall(
    uint64_t num,
    uint64_t a0,
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5)
{
    syscall_msgs[0].callnum = num;
    syscall_msgs[1].params[0] = a0;
    syscall_msgs[1].params[1] = a1;
    syscall_msgs[1].params[2] = a2;
    syscall_msgs[1].params[3] = a3;
    syscall_msgs[1].params[4] = a4;
    syscall_msgs[1].params[5] = a5;
    sfence();
    outb(0x01, 0);
}

static void init_static_data(void)
{
    int size = &DATA_VIRT_END - &DATA_VIRT_START;
    for (int i = 0; i < size; i++) {
        (&DATA_VIRT_START)[i] = (&DATA_LOAD_START)[i];
    }

    size = &BSS_VIRT_END - &BSS_VIRT_START;
    for (int i = 0; i < size; i++) {
        (&BSS_VIRT_START)[i] = 0;
    }
}

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void)
{
    init_static_data();

    int brand_index;
    int cpu_id;
    cpuid(0x01, &brand_index, &cpu_id);

    // asm("sti");

    start_syscall(
        1,                    // write
        1,                    // file descriptor to write (stdout)
        (uint64_t) "Hello\n", // data to write
        6,                    // length of data
        0,
        0,
        0);

    // Spin until the system call is complete.
    while (syscall_msgs[0].callnum != SYSCALL_COMPLETE) {
    }

    int acc;
    for (int i = 0; i < 80; i++) {
        outb(0xE9, '-');
        acc++;
    }

    const char *p;
    for (p = "\nHello, world!\n"; *p; ++p) {
        outb(0xE9, *p);
        acc += *p;
    }

    // Bridge-specific shutdown signal.
    outb(0x8900, 0);

    // If the above I/O doesn't shut down for some reason, we'll just halt
    // forever instead.
    for (;;) {
        asm("hlt" : /* empty */ : "a"(42) : "memory");
    }
}
