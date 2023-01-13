#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
  char filename[256];
  u64 bytes_written;
};

struct bpf_map_def SEC("maps") data_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

SEC("tp/sys_enter")
int on_sys_enter(struct pt_regs *ctx) {
  int syscall_nr = PT_REGS_SYSCALL_NR(ctx);
  u64 pid = bpf_get_current_pid_tgid();

  if (syscall_nr != __NR_write) {
    return 0;
  }

  struct data_t data = {};
  struct file *file = (struct file *)PT_REGS_PARM2(ctx);
  bpf_probe_read_str(data.filename, sizeof(data.filename),
                     file->f_path.dentry->d_name.name);
  data.bytes_written = PT_REGS_PARM3(ctx);

  bpf_perf_event_output(ctx, &data_map, 0, &data, sizeof(data));
  return 0;
}

char _license[] SEC("license") = "GPL";
