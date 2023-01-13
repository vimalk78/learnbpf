
#ifndef __PREFIX_H__
#define __PREFIX_H__

#define MAX_FILE_NAME_LENGTH 256

#define VAR_LOG_PODS "/home/vimalkum/src/ebpf/learnbpf/bpftrace/first"
const char LOG_DIR[sizeof(VAR_LOG_PODS) + 1] = VAR_LOG_PODS;
#define LEN_LOG_DIR sizeof(LOG_DIR)

struct KeyPidFd {
  unsigned long tgid_pid;
  long fd;
};
#endif
