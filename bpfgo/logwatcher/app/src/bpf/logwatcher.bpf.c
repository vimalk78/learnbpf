#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/version.h>

#define MAX_FILE_NAME_LENGTH 128

size_t strlen_(const char *s);
int strncmp_(const char *cs, const char *ct, size_t count);
int strncmp2_(const char *cs, const char *ct, size_t count);

#define FIRST_32_BITS(x) x >> 32
#define LAST_32_BITS(x) x & 0xFFFFFFFF

//#define LOG_DIR "/home/vimalkum/src/ebpf/learnbpf/bpftrace/first"
#define LOG_DIR "/var/log/pods"
// const char *LOG_DIR = "/home/vimalkum/src/ebpf/learnbpf/bpftrace/first";
#define LEN_LOG_DIR sizeof(LOG_DIR)
// const int LEN_LOG_DIR = 46;
int matchPrefix(char str[MAX_FILE_NAME_LENGTH]);
// int matchPrefix(const char *str);

struct syscall_enter_openat_args_t {
  u64 _unused1;
  u64 _unused2;

  u64 dfd;
  const char *filename;
};

struct syscall_exit_openat_args_t {
  u64 _unused1;
  u64 _unused2;

  long ret;
};

struct syscall_enter_write_args_t {
  u64 _unused1;
  u64 _unused2;

  unsigned int fd;
  const char *buf;
  size_t count;
};

struct syscall_enter_close_args_t {
  u64 _unused1;
  u64 _unused2;

  unsigned int fd;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, char[MAX_FILE_NAME_LENGTH]);
} ctx_syscall_open SEC(".maps");

struct KeyPidFd {
  u64 pid;
  long fd;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct KeyPidFd);
  __type(value, char[MAX_FILE_NAME_LENGTH]);
} fd_to_path_for_pid SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int syscall_enter_open(struct syscall_enter_openat_args_t *args) {

  char filename[MAX_FILE_NAME_LENGTH];
  bpf_probe_read_user(filename, sizeof(filename), args->filename);
  if (matchPrefix(filename) != 0) {
    // bpf_printk("syscall_enter_open returning \"%s\" ...", args->filename);
    return 0;
  }
  bpf_printk("syscall_enter_open called...");

  if (strlen_(args->filename) > MAX_FILE_NAME_LENGTH) {
    return 0;
  }

  u64 pid_tgid;
  pid_tgid = bpf_get_current_pid_tgid();

  long ret = bpf_map_update_elem(&ctx_syscall_open, &pid_tgid,
                                 (const void *)args->filename, BPF_ANY);
  return ret;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int syscall_exit_open(struct syscall_exit_openat_args_t *args) {

  u64 pid_tgid;
  pid_tgid = bpf_get_current_pid_tgid();

  void *lookup_ret = bpf_map_lookup_elem(&ctx_syscall_open, &pid_tgid);

  if (lookup_ret == NULL) {
    return 0;
  }

  // char *path = (char *)lookup_ret;
  if (args->ret > 0) {
    // save {(fd,pid) => path} mapping
    struct KeyPidFd pf;
    pf.pid = pid_tgid;
    pf.fd = args->ret;
    int ret =
        bpf_map_update_elem(&fd_to_path_for_pid, &pf, lookup_ret, BPF_ANY);
    if (ret != 0) {
      return ret;
    }
  }

  // remove entry for pid
  return bpf_map_delete_elem(&ctx_syscall_open, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall_enter_write(struct syscall_enter_write_args_t *args) {

  u64 pid_tgid;
  pid_tgid = bpf_get_current_pid_tgid();

  struct KeyPidFd pf;
  pf.pid = pid_tgid;
  pf.fd = args->fd;
  void *lookup_ret = bpf_map_lookup_elem(&fd_to_path_for_pid, &pf);
  char *path = (char *)lookup_ret;
  if (path == NULL) {
    return -1;
  }

  // print path,count
  bpf_printk("called...");
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int syscall_enter_close(struct syscall_enter_close_args_t *args) {

  u64 pid_tgid;
  pid_tgid = bpf_get_current_pid_tgid();

  struct KeyPidFd pf;
  pf.pid = pid_tgid;
  pf.fd = args->fd;
  return bpf_map_delete_elem(&fd_to_path_for_pid, &pf);
}

size_t strlen_(const char *s) {
  const char *sc;

  for (sc = s; *sc != '\0'; ++sc)
    /* nothing */;
  return sc - s;
}

int strncmp_(const char *s1, const char *s2, size_t n) {
  if (n == 0)
    return (0);
  do {
    if (*s1 != *s2++)
      return (*(unsigned char *)s1 - *(unsigned char *)--s2);
    if (*s1++ == 0)
      break;
  } while (--n != 0);
  return (0);
}

int strncmp2_(const char *cs, const char *ct, size_t count) {
  unsigned char c1, c2;

  while (count) {
    c1 = *cs;
    c2 = *ct;
    if (c1 != c2)
      return c1 < c2 ? -1 : 1;
    cs++;
    ct++;
    if (!c1)
      break;
    count--;
  }
  return 0;
}

// int matchPrefix(const char *str) {
int matchPrefix(char str[MAX_FILE_NAME_LENGTH]) {
  for (int i = 0; i < LEN_LOG_DIR; i++) {
    char ch1 = LOG_DIR[i];
    if (ch1 == '\0') {
      return 0;
    }
    char ch2 = str[i];
    if (ch2 == '\0') {
      return -1;
    }
    if (ch1 != ch2) {
      return -2;
    }
  }
  return (-3);
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
