#include <stddef.h>
#include <stdint.h>

extern char DATA_LOAD_START;
extern char DATA_VIRT_START;
extern char DATA_VIRT_END;
extern char BSS_VIRT_START;
extern char BSS_VIRT_END;

static inline void outb(uint16_t port, uint8_t value)
{
    asm("outb %0,%1" : /* empty */ : "a"(value), "Nd"(port) : "memory");
}

static inline void cpuid(int code, uint32_t *a, uint32_t *d)
{
    asm volatile("cpuid" : "=a"(*a), "=d"(*d) : "a"(code) : "ecx", "ebx");
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

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void)
{
    int brand_index;
    int cpu_id;
    cpuid(0x01, &brand_index, &cpu_id);

    // asm("sti");

    /*const char *p;

    for (p = "Hello, world!\n"; *p; ++p)
        outb(0xE9, *p);

    *(long *)0x400 = 42;*/

    // outb(0xe9, 'H');
    // outb(0xe9, 'e');
    // outb(0xe9, 'l');
    // outb(0xe9, 'l');
    // outb(0xe9, 'o');

    // Placeholder syscall device notification. This is not fully implemented
    // on either side yet, but this is here just to test that the notification
    // makes it through to the virtual device in the bridge.
    outb(0x01, 0);

    const char *p;
    int acc;
    for (p = "Hello, world!\n"; *p; ++p) {
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
