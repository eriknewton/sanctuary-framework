/* Capability: launch admission reads filesystem ids and inheritable capabilities. P3. */
#define _GNU_SOURCE
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <grp.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "inh") || getuid() != 0) return 2;
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[2] = {{0}};
  if (syscall(SYS_capget, &header, caps)) return 3;
  if (!strcmp(argv[1], "inh")) caps[0].inheritable |= 1U << CAP_NET_RAW;
  if (syscall(SYS_capset, &header, caps)) return 4;
  /* Linux capability indexes run through CAP_LAST_CAP, inclusive. */
  for (int cap=0; cap<=CAP_LAST_CAP; cap++) if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return 5;
  if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) || setgroups(0, 0) || setresgid(60123,60123,60123) || setresuid(60123,60123,60123)) return 6;
  /* Retain only the transient right to construct a mismatched filesystem id. */
  caps[0].permitted = caps[0].effective = (1U << CAP_SETUID) | (1U << CAP_SETGID);
  caps[1].permitted = caps[1].effective = 0;
  if (syscall(SYS_capset, &header, caps)) return 7;
  caps[0].permitted = caps[0].effective = 0;
  if (syscall(SYS_capset, &header, caps) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 8;
  execl("/usr/local/libexec/sanctuary/protected-agent-v1", "protected-agent-v1", (char *)0);
  return 9;
}
