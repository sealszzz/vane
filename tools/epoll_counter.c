#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
static unsigned long waits, adds, mods, dels;
int epoll_wait(int fd, struct epoll_event *ev, int n, int timeout) {
    static int (*real_call)(int,struct epoll_event*,int,int);
    if (!real_call) *(void **)(&real_call)=dlsym(RTLD_NEXT,"epoll_wait");
    waits++;
    return real_call(fd,ev,n,timeout);
}
int epoll_ctl(int fd,int op,int sock,struct epoll_event *ev) {
    static int (*real_call)(int,int,int,struct epoll_event*);
    if (!real_call) *(void **)(&real_call)=dlsym(RTLD_NEXT,"epoll_ctl");
    if (op==EPOLL_CTL_ADD) adds++;
    else if (op==EPOLL_CTL_MOD) mods++;
    else if (op==EPOLL_CTL_DEL) dels++;
    return real_call(fd,op,sock,ev);
}
__attribute__((destructor)) static void report(void) {
    const char *path=getenv("VANE_EPOLL_COUNTS");
    if (!path) return;
    FILE *f=fopen(path,"w");
    if(f){fprintf(f,"{\"wait\":%lu,\"add\":%lu,\"mod\":%lu,\"del\":%lu}\n",waits,adds,mods,dels);fclose(f);}
}
