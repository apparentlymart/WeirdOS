
#include "bridge.h"
#include "vm.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rom-filename>\n\n", argv[0]);
        return 1;
    }

    char *rom_fn = argv[1];
    int rom_fd = open(rom_fn, O_RDONLY);
    if (rom_fd < 0) {
        perror("Opening ROM file");
        return 1;
    }

    Bridge br;
    if (bridge_open(&br, rom_fd) < 0) {
        perror("bridge_open");
        return 1;
    }

    printf("KVM file descriptor %d\n", br.kvm.fd);
    printf("VM file descriptor %d\n", br.vm.fd);
    printf("VCPU file descriptor %d\n", br.cpus[0].fd);

    if (bridge_close(&br) < 0) {
        perror("bridge_close");
        return 1;
    }
    if (close(rom_fd) < 0) {
        perror("Closing ROM file");
        return 1;
    }
    return 0;
}
