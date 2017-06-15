#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <stdlib.h>

void* dbg_dlopen(const char* path, int flag){
     printf("path is %s, flag is 0x%x!\n", path, flag);
     void* h = dlopen(path, flag);
     printf("dlopen return %p, err %s", h, dlerror());
     return h;
}

void test1(void){
     printf("hello world!\n");
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}

void test2(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void test3(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void test4(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void test5(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void test6(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void test7(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void test8(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}

int main(){     
     void* addr = (void*)dlopen;
     printf("dlopen @ %p, sizeof(int) is 0x%lx!\n", addr, sizeof(int));

     test1();
     test2();
     test3();
     test4();
     test5();
     test6();
     test7();
     test8();
     //atexit(abort);
     /* void* h = dlopen("/home/gpmn/Workspace/goinside/Test/libgoinside.so", 0x102); */
     /* if(!h){ */
     /*      printf("dlopen failed with errno %d, %s\n", errno, dlerror()); */
     /* } */

     for(int idx = 0; idx < 100000000; idx ++){
          usleep(1000000);
          printf("%d - %d\n", getpid(), idx);
     }
     void *kkk = dlopen;
     printf("%p\n", kkk);
}

void kkk0(void){
     printf("hello world!\n");
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk1(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk2(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk3(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk4(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk5(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk6(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk7(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
void kkk8(void){
     printf("line @%d : hello world!\n", __LINE__);
     time_t tm;
     tm = time(NULL);
     ctime(&tm);
}
