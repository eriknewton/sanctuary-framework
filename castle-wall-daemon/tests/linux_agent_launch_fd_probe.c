/* Capability: descriptor closure and second-exec identity. P3. */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Must match LAUNCHER_PATH in src/linux_install/contract.rs. */
#define LAUNCHER "/usr/local/libexec/sanctuary/protected-agent-v1"
static unsigned long long start_ticks(void) {
    FILE *f=fopen("/proc/self/stat","r");char line[4096];if(!f || !fgets(line,sizeof(line),f))exit(6);fclose(f);
    char *tail=strrchr(line,')'),*save=0;if(!tail)exit(7);char *field=strtok_r(tail+1," ",&save);
    /* Field 22 follows the comm field 2; tail begins at field 3. */
    for(int n=3;n<22 && field;n++)field=strtok_r(0," ",&save);
    if(!field)exit(8);return strtoull(field,0,10);
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--chain")) {
        FILE *f=fopen("/var/lib/sanctuary-agent-workspace/fd-probe-before.txt","w");if(!f)return 9;
        fprintf(f,"pid=%ld\nstart_ticks=%llu\n",(long)getpid(),start_ticks());fclose(f);
        execl(LAUNCHER,LAUNCHER,(char *)0);return 10;
    }
    DIR *d=opendir("/proc/self/fd"); int count=0; struct dirent *entry;
    if(!d) return 2;
    while((entry=readdir(d))) { char *end; long fd=strtol(entry->d_name,&end,10); if(!*end && fd>2 && fd!=dirfd(d)) count++; }
    closedir(d);
    FILE *out=fopen("/var/lib/sanctuary-agent-workspace/fd-probe.txt","w"); if(!out) return 3;
    char cwd[4096]; if(!getcwd(cwd,sizeof(cwd))) return 4;
    fprintf(out,"pid=%ld\nfds=%d\ncwd=%s\nstart_ticks=%llu\n",(long)getpid(),count,cwd,start_ticks());
    for(int fd=0;fd<=2;fd++) {char path[64],dest[4096];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);ssize_t n=readlink(path,dest,sizeof(dest)-1);if(n<0)return 5;dest[n]=0;fprintf(out,"stdio%d=%s\n",fd,dest);}
    fclose(out);return 0;
}
