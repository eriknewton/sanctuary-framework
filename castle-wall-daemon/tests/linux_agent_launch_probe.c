/* Capability: native and alternate-ABI confinement under the shipped unit. P3. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/syscall.h>
int main(void) {
  FILE *f=fopen("/var/lib/sanctuary-agent-workspace/p3-sandbox.tmp","w");
  if(!f) return 2;
  DIR *d=opendir("/proc/self/fd");int foreign=0;struct dirent *entry;
  while(d && (entry=readdir(d))){char *end;long fd=strtol(entry->d_name,&end,10);if(!*end && fd>2 && fd!=fileno(f) && fd!=dirfd(d))foreign++;}
  if(d)closedir(d);fprintf(f,"inherited_fds %d\n",foreign);
  int families[]={AF_UNIX,AF_NETLINK,AF_PACKET,AF_INET,AF_INET6};
  for(int i=0;i<5;i++){errno=0;int fd=socket(families[i],SOCK_DGRAM,0);fprintf(f,"family %d fd %d errno %d\n",families[i],fd,errno);if(fd>=0)close(fd);}
  int flags[]={CLONE_NEWUSER,CLONE_NEWNET,CLONE_NEWNS,CLONE_NEWPID,CLONE_NEWUTS,CLONE_NEWIPC,CLONE_NEWCGROUP};
  for(int i=0;i<7;i++){errno=0;int r=unshare(flags[i]);fprintf(f,"namespace %d result %d errno %d\n",flags[i],r,errno);}
  for(int i=0;i<7;i++){errno=0;long r=syscall(SYS_clone,flags[i]|SIGCHLD,0,0,0,0);if(r==0)_exit(0);int saved=errno;if(r>0)waitpid((pid_t)r,0,0);fprintf(f,"clone_namespace %d result %ld errno %d\n",flags[i],r,saved);}
  int nsfd=open("/proc/self/ns/net",O_RDONLY);errno=0;int sr=setns(nsfd,CLONE_NEWNET);fprintf(f,"setns result %d errno %d\n",sr,errno);if(nsfd>=0)close(nsfd);
  const char *paths[]={"/tmp/p3-write","/var/tmp/p3-write","/dev/shm/p3-write","/run/user/p3-write","/dev/p3-write","/etc/p3-write","/sys/p3-write","/sys/fs/cgroup/p3-write","/var/lib/p3-write"};
  for(int i=0;i<9;i++){errno=0;int fd=open(paths[i],O_CREAT|O_WRONLY|O_EXCL,0600);fprintf(f,"write %s fd %d errno %d\n",paths[i],fd,errno);if(fd>=0){close(fd);unlink(paths[i]);}}
  const char *devices[]={"/dev/null","/dev/zero","/dev/full"};
  for(int i=0;i<3;i++){errno=0;int dev=open(devices[i],O_WRONLY|O_NONBLOCK);ssize_t n=dev<0?-1:write(dev,"device-probe",12);int saved=errno;if(dev>=0)close(dev);fprintf(f,"device %s written %zd errno %d\n",devices[i],n,saved);}
  const char *api[]={"/proc/sys/kernel/hostname","/proc/sysrq-trigger","/sys/fs/cgroup/cgroup.procs"};
  for(int i=0;i<3;i++){errno=0;int fd=open(api[i],O_WRONLY|O_NONBLOCK);int saved=errno;if(fd>=0)close(fd);fprintf(f,"api_write %s fd %d errno %d\n",api[i],fd,saved);}
  errno=0;int r=setuid(0);fprintf(f,"setuid0 result %d errno %d\n",r,errno);
  /* One page and one queue witness activation-local IPC lifetime. */
  int shm=shmget(IPC_PRIVATE,4096,IPC_CREAT|0600);
  int msg=msgget(IPC_PRIVATE,IPC_CREAT|0600);
  fprintf(f,"ipc shm %d msg %d\n",shm,msg);
  fflush(f);
  pid_t p=fork();if(p==0){
    /* int 0x80 dispatches an alternate x86 ABI. getpid=20 has no pointers. */
    unsigned long result;asm volatile("int $0x80":"=a"(result):"a"(20):"memory");
    _exit(result>0?42:43);
  }
  int status=0;waitpid(p,&status,0);fprintf(f,"alternate_abi status %d signal %d\n",status,WIFSIGNALED(status)?WTERMSIG(status):0);
  p=fork();if(p==0){long r=syscall(0x40000000UL|SYS_getpid);_exit(r>0?42:43);}waitpid(p,&status,0);fprintf(f,"x32_abi signal %d\n",WIFSIGNALED(status)?WTERMSIG(status):0);
  /* Fixed policy ceilings; one extra admission demonstrates each refusal. */
  int fd=open("/var/lib/sanctuary-agent-workspace/flood-bytes",O_CREAT|O_WRONLY|O_EXCL,0600);char chunk[4096]={0};size_t total=0;
  while(fd>=0 && total<65UL*1024*1024){ssize_t n=write(fd,chunk,sizeof(chunk));if(n<0)break;total+=(size_t)n;}int bytes_errno=errno;if(fd>=0)close(fd);unlink("/var/lib/sanctuary-agent-workspace/flood-bytes");
  fprintf(f,"byte_flood bytes %zu errno %d\n",total,bytes_errno);
  int files=0;char path[256];
  for(int i=0;i<=4096;i++){snprintf(path,sizeof(path),"/var/lib/sanctuary-agent-workspace/inode-%d",i);fd=open(path,O_CREAT|O_EXCL|O_WRONLY,0600);if(fd<0)break;close(fd);files++;}int inode_errno=errno;
  for(int i=0;i<files;i++){snprintf(path,sizeof(path),"/var/lib/sanctuary-agent-workspace/inode-%d",i);unlink(path);}fprintf(f,"inode_flood files %d errno %d\n",files,inode_errno);
  pid_t children[65];int count=0;
  while(count<65){p=fork();if(p<0)break;if(p==0){for(;;)pause();}children[count++]=p;}int fork_errno=errno;
  for(int i=0;i<count;i++)kill(children[i],SIGKILL);for(int i=0;i<count;i++)waitpid(children[i],0,0);fprintf(f,"fork_flood children %d errno %d\n",count,fork_errno);
  fclose(f);rename("/var/lib/sanctuary-agent-workspace/p3-sandbox.tmp","/var/lib/sanctuary-agent-workspace/p3-sandbox.txt");for(;;) pause();
}
