
#include "bridge.h"
#include "vm.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    Bridge br;
    if (bridge_open(&br, 0) < 0) {
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
    return 0;
}
