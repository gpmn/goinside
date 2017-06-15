#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <string.h>

void __attribute__((constructor)) test_auto_load(void) {
   printf("test_auto_load is called!\n");
}

int64_t gullPortNum = -1;
int64_t goin_get_service_port(void){
    return gullPortNum;
}

void PtraceDetachWrapper(pid_t pid){
     if (0 != ptrace(PTRACE_DETACH, pid, 0, 0)){
         printf("ptrace detach %d failed, err %d : %s\n", pid, errno, strerror(errno));
     }else{
        printf("ptrace detach is OK");
     }
}