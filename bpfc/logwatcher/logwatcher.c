#include "logwatcher.skel.h"
#include "prefix.h"
#include <bpf/bpf.h>
#include <signal.h>
#include <sys/resource.h>

int ctx_openat_map_fd;
int fd_to_filepath_map_fd;

static void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

void print_openat_ctx_map() {
  unsigned long pid_tgid;
  while (bpf_map_get_next_key(ctx_openat_map_fd, &pid_tgid, &pid_tgid) != -1) {
    char filename[MAX_FILE_NAME_LENGTH];
    int ret;
    ret = bpf_map_lookup_elem(ctx_openat_map_fd, &pid_tgid, filename);
    if (ret != 0) {
      fprintf(stderr, "failed to lookup element\n");
      exit(-1);
    }
    fprintf(stderr, "%lu: %s", pid_tgid, filename);
  }
}

void print_fd_to_path_map() {
  struct KeyPidFd key;
  while (bpf_map_get_next_key(fd_to_filepath_map_fd, &key, &key) != -1) {
    char filename[MAX_FILE_NAME_LENGTH];
    int ret;
    ret = bpf_map_lookup_elem(fd_to_filepath_map_fd, &key, filename);
    if (ret != 0) {
      fprintf(stderr, "failed to lookup element\n");
      exit(-1);
    }
    int tid = key.tgid_pid >> 32;
    unsigned int tgid = key.tgid_pid & 0xffffffff;
    unsigned int pid = key.tgid_pid >> 32;
    fprintf(stderr, "{pid: %d, tgid: %d, fd: %lu} : %s\n", pid, tgid, key.fd,
            filename);
  }
}

void sig_handler(int signum) {
  printf("\nInside handler function\n");
  // signal(SIGINT, SIG_DFL); // Re Register signal handler for default action
  print_openat_ctx_map();
  print_fd_to_path_map();

  exit(-1);
}

int main(int argc, char **argv) {

  bump_memlock_rlimit();

  struct logwatcher *skel = logwatcher__open();
  int ret = logwatcher__load(skel);
  if (ret != 0) {
    fprintf(stderr, "load failed. err: %d\n", ret);
    return -1;
  }
  fprintf(stderr, "logwatcher loaded...\n");
  signal(SIGINT, sig_handler);
  ctx_openat_map_fd = bpf_map__fd(skel->maps.ctx_syscall_open);
  fd_to_filepath_map_fd = bpf_map__fd(skel->maps.fd_to_path_for_pid);
  ret = logwatcher__attach(skel);
  if (ret != 0) {
    fprintf(stderr, "attach failed. err: %d\n", ret);
    return -2;
  }
  fprintf(stderr, "logwatcher attached...\n");
  for (;;) {
  }
  return 0;
}
