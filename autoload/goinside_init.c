#include <stdio.h>

extern void goinRPCInit();
void __attribute__((constructor)) test_auto_load(void) {
    printf("test_auto_load is called\n");
    goinRPCInit();
}



