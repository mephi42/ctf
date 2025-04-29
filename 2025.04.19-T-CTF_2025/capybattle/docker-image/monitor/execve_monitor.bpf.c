#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#define EPERM 1
#define E2BIG 7
#define ENOMEM 12
#define EFAULT 14

#define MAX_ENV_VARS 128
#define MAX_STRINGS_SIZE (1 << 14)

struct event {
    int env_offsets[MAX_ENV_VARS];
    char strings[MAX_STRINGS_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} event_storage SEC(".maps");

static int fill_event(struct event *e, const char *pathname, const char **envp)
{
    int i, env_idx = 0, state = 0;
    const char *env_var;
    bool found = false;
    int err;

    // Use bpf_for() instead of a for loop, otherwise the verifier will not be
    // able to check that many iterations.
    bpf_for(i, 0, MAX_STRINGS_SIZE) {
        switch (state) {
        case 0:
           err = bpf_probe_read_user(&e->strings[i], 1, pathname++);
           if (e->strings[i] == 0) {
                state = 100;
           }
           break;
        case 100:
            err = bpf_probe_read_user(&env_var, sizeof(env_var), envp++);
            if (err < 0) {
                return err;
            }
            if (env_var == NULL) {
                return found ? i : 0;
            }
            if (env_idx >= MAX_ENV_VARS) {
                return -E2BIG;
            }
            e->env_offsets[env_idx++] = i;
            state = 101;
            /* fallthrough */
        default:
            err = bpf_probe_read_user(&e->strings[i], 1, env_var++);
            if (err < 0) {
                return err;
            }
            switch (state) {
                case 101: state = e->strings[i] == 'L' ? 102 : 999; break;
                case 102: state = e->strings[i] == 'D' ? 103 : 999; break;
                case 103: state = e->strings[i] == '_' ? 104 : 999; break;
                case 104: state = e->strings[i] == 'P' ? 105 : 999; break;
                case 105: state = e->strings[i] == 'R' ? 106 : 999; break;
                case 106: state = e->strings[i] == 'E' ? 107 : 999; break;
                case 107: state = e->strings[i] == 'L' ? 108 : 999; break;
                case 108: state = e->strings[i] == 'O' ? 109 : 999; break;
                case 109: state = e->strings[i] == 'A' ? 110 : 999; break;
                case 110: state = e->strings[i] == 'D' ? 111 : 999; break;
                case 111: found |= (e->strings[i] == '='); state = 999; break;
            }
            if (e->strings[i] == 0) {
                state = 100;
            }
            break;
        }
    }

    return -E2BIG;
}

SEC("fmod_ret/__x64_sys_execve")
long BPF_PROG(handle_execve, struct pt_regs *regs, int ret)
{
    const char *pathname;
    const char **envp;
    struct event *e;
    __u32 key = 0;
    int err;

    // Read the arguments
    pathname = (const char *)PT_REGS_PARM1(regs);
    envp = (const char **)PT_REGS_PARM3(regs);
    
    // Allocate event storage
    e = bpf_map_lookup_elem(&event_storage, &key);
    if (!e) {
        return -EFAULT;
    }

    // Copy all environment variables
    err = fill_event(e, pathname, envp);
    if (err == 0) {
        // No LD_PRELOAD found
        return ret;
    }
    if (err < 0) {
        return err;
    }

    // Submit only the filled portion of the event
    int size = offsetof(struct event, strings) + err;
    if (bpf_ringbuf_output(&rb, e, size, 0) < 0) {
        return -ENOMEM;
    }

    // Block the execve call
    return -EPERM;
} 