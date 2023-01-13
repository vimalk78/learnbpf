#include "logwatcher.skel.h"
#include <sys/resource.h>

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

int main(int argc, char **argv) {

  bump_memlock_rlimit();

  struct logwatcher *skel = logwatcher__open();
  int ret = logwatcher__load(skel);
  if (ret != 0) {
    fprintf(stderr, "load failed. err: %d\n", ret);
  }
  ret = logwatcher__attach(skel);
  if (ret != 0) {
    fprintf(stderr, "attach failed. err: %d\n", ret);
  }
  fprintf(stderr, "logwatcher attached...\n");
  for (;;) {
  }
  return 0;
}
