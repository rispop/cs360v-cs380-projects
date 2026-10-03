/* container.c: STUDENT IMPLEMENTATION FILE for Project 2.
 *
 * You implement a minimal container runtime here. main.c parses the command
 * line and calls container_run(); everything after that is yours.
 *
 * The TODOs below are the checklist: what to call and in what order. SPEC.md
 * explains what each mechanism is and why the order matters, and is the
 * contract if the two ever disagree.
 *
 * As shipped, container_run() returns 1 and nothing runs, so no checks pass.
 * Start by getting the command to execute: that needs container_run() and
 * container_init() to spawn it and container_setup() to pivot into the rootfs,
 * because the command lives inside the rootfs.
 *
 * Provided: main.c (argument parsing), util.c (write_file()), net.c (the --net
 * host side), container.h (the struct, the declarations, the stack size).
 */
#define _GNU_SOURCE
#include "container.h"

#include <sched.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <net/route.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <fcntl.h>

#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#define SECCOMP_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture for seccomp filter"
#endif

/* ---- Part I: namespaces ----------------------------------------------- */

int container_namespaces(void)
{
    /* TODO(student): return the bitwise-OR of CLONE_NEWUSER, CLONE_NEWPID,
     * CLONE_NEWNS, CLONE_NEWUTS and CLONE_NEWNET. Returning 0 gives no
     * isolation at all. */
    return CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET;
}

int container_write_idmaps(struct container *c, pid_t child)
{
    (void)c; (void)child;
    /* TODO(student): a USER namespace starts with an EMPTY uid/gid map, so the
     * child cannot do anything until you write one. Write, using write_file():
     *   /proc/<child>/uid_map     <- "0 <your-uid> 1"
     *   /proc/<child>/setgroups   <- "deny"      (required before gid_map)
     *   /proc/<child>/gid_map     <- "0 <your-gid> 1"
     * This maps container id 0 (root) to your real id outside. See getuid(2). */
    char uid_out[100];
    char set_group_out[100];
    char gid_map_out[100];
    if (sprintf(uid_out, "/proc/%d/uid_map", child) < 0) {
        return -1;
    }
    if (sprintf(set_group_out, "/proc/%d/setgroups", child) < 0) {
        return -1;
    }
    if (sprintf(gid_map_out, "/proc/%d/gid_map", child) < 0) {
        return -1;
    }

    char uid_txt[100];
    uid_t uid = getuid();

    char gid_txt[100];
    gid_t gid = getgid();

    if (sprintf(uid_txt, "0 %u 1", uid) < 0) {
        return -1;
    }
    
    if (sprintf(gid_txt, "0 %u 1", gid) < 0) {
        return -1;
    }

    if (write_file(uid_out, uid_txt) == -1 || write_file(set_group_out, "deny") == -1 || write_file(gid_map_out, gid_txt) == -1) {
        return -1;   
    }
    return 0;
}

/* ---- Part V: cgroup --------------------------------------------------- */

int container_cgroup_init(struct container *c)
{
    (void)c;
    /* TODO(student): create this container's cgroup and set its limits (SPEC
     * Part V):
     *   - enable the controllers you need in the BASE cgroup's subtree_control:
     *       write "+pids +memory" to <cgroup_base>/cgroup.subtree_control;
     *   - mkdir <cgroup_base>/<name>  and store that path in c->cg_path
     *     (cleanup needs it);
     *   - write c->pids_max to <cg_path>/pids.max and c->mem_max to
     *     <cg_path>/memory.max (a value < 0 means the literal string "max"), and
     *     write "0" to <cg_path>/memory.swap.max so hitting the memory cap
     *     OOM-kills instead of swapping. */
    char path[PATH_MAX + 64];
    char val[64];

    snprintf(path, sizeof(path), "%s/cgroup.subtree_control", c->cgroup_base);
    if (write_file(path, "+pids +memory") < 0) return -1;

    snprintf(c->cg_path, sizeof(c->cg_path), "%s/%s", c->cgroup_base, c->name);
    if (mkdir(c->cg_path, 0755) < 0) {
        if (errno != EEXIST) {
            perror("container: mkdir cgroup");
            return -1;
        }
    }

    snprintf(path, sizeof(path), "%s/pids.max", c->cg_path);
    if (c->pids_max < 0) {
        if (write_file(path, "max") < 0) return -1;
    } else {
        snprintf(val, sizeof(val), "%ld", c->pids_max);
        if (write_file(path, val) < 0) return -1;
    }

    snprintf(path, sizeof(path), "%s/memory.max", c->cg_path);
    if (c->mem_max < 0) {
        if (write_file(path, "max") < 0) return -1;
    } else {
        snprintf(val, sizeof(val), "%ld", c->mem_max);
        if (write_file(path, val) < 0) return -1;
    }

    snprintf(path, sizeof(path), "%s/memory.swap.max", c->cg_path);
    if (write_file(path, "0") < 0) return -1;

    return 0;
}

int container_cgroup_enter(struct container *c, pid_t child)
{
    (void)c; (void)child;
    /* TODO(student): move `child` into this container's cgroup by writing its
     * pid to <cg_path>/cgroup.procs. */
    char path[PATH_MAX + 64];
    char pid_str[32];

    snprintf(path, sizeof(path), "%s/cgroup.procs", c->cg_path);
    snprintf(pid_str, sizeof(pid_str), "%d", child);

    if (write_file(path, pid_str) < 0) {
        return -1;
    }
    return 0;
}

/* ---- Parts I/II/III: isolation, run inside the container init --------- */

int container_setup(struct container *c)
{
    (void)c;
    /* Runs inside the container's init, after the parent has written your id
     * maps and put you in the cgroup, and before you launch the command.
     *
     * TODO(student) Part I   - set the hostname to c->hostname (sethostname(2)).
     *
     * TODO(student) Part I   - call container_network() to bring up loopback
     *     (before the capability drop; it needs CAP_NET_ADMIN).
     *
     * TODO(student) Part I   - if c->net_enabled, call container_net_config(c)
     *     to set up the veth the host provided (also before the cap drop).
     *
     * TODO(student) Part II  - isolate the filesystem, pivoting into c->rootfs:
     *     1. make mount propagation private so your mounts don't leak to the
     *        host:  mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
     *     2. bind c->rootfs onto itself, then remount that bind read-only;
     *     3. mount a writable tmpfs on <rootfs>/tmp;
     *     4. mount a tmpfs on <rootfs>/dev and bind /dev/null and /dev/zero in
     *        (you cannot mknod(2) in a user namespace);
     *     5. mount a fresh /proc on <rootfs>/proc, BEFORE switching roots: a
     *        new /proc can only be mounted in a user namespace while another
     *        /proc is still visible, so doing it after detaching the old root
     *        fails with EPERM;
     *     6. pivot_root(2) into c->rootfs and detach the old root, chdir("/").
     *
     * TODO(student) Part III - drop all capabilities so container-root is
     *     powerless: empty the bounding set (prctl PR_CAPBSET_DROP for every cap
     *     0..CAP_LAST_CAP), clear the permitted/effective/inheritable sets
     *     (capset(2)), and set PR_SET_NO_NEW_PRIVS. Do this near-last, so the
     *     steps above still have the privileges they need.
     *
     * TODO(student) Part III - then call container_seccomp() to install the
     *     syscall filter (do it last of all).
     *
     * Return 0 on success, -1 to abort. */


    // part 1 stuff
    if (sethostname(c->hostname, strlen(c->hostname)) == -1 || container_network() == -1) {
        return -1;
    }
    if (c->net_enabled) {
        if (container_net_config(c) == -1) {
            return -1;
        }
    }

    // part 2 stuff
    char path[PATH_MAX];
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("mount private");
        return -1;
    }
    if (mount(c->rootfs, c->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0) return -1;
    if (mount(c->rootfs, c->rootfs, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) return -1;

    snprintf(path, sizeof(path), "%s/tmp", c->rootfs);
    if (mount("tmpfs", path, "tmpfs", 0, NULL) < 0) return -1;

    snprintf(path, sizeof(path), "%s/dev", c->rootfs);
    if (mount("tmpfs", path, "tmpfs", 0, NULL) < 0) return -1;

    snprintf(path, sizeof(path), "%s/dev/null", c->rootfs);
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0) close(fd);
    if (mount("/dev/null", path, NULL, MS_BIND, NULL) < 0) return -1;

    snprintf(path, sizeof(path), "%s/dev/zero", c->rootfs);
    fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0) close(fd);
    if (mount("/dev/zero", path, NULL, MS_BIND, NULL) < 0) return -1;

    snprintf(path, sizeof(path), "%s/proc", c->rootfs);
    if (mount("proc", path, "proc", 0, NULL) < 0) return -1;

    if (chdir(c->rootfs) < 0) return -1;
    if (syscall(SYS_pivot_root, ".", ".") < 0) {
        perror("pivot_root");
        return -1;
    }
    if (umount2(".", MNT_DETACH) < 0) return -1;
    if (chdir("/") < 0) return -1;

    // part 3 stuff

    /*
    drop all capabilities
    remove access to setuid so that we cannot get capabilities back
    
    Obliterate the permissions
    */
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
    }

    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capset, &hdr, data) < 0) {
        perror("capset");
        return -1;
    }
    if (container_seccomp() < 0) return -1;
    
    return 0;
}

int container_network(void)
{
    /* TODO(student) Part I: the container has its own NET namespace, so it starts
     * with only a `lo` interface that is DOWN. Bring it UP so localhost works:
     * open an AF_INET SOCK_DGRAM socket, fill a `struct ifreq` with ifr_name
     * "lo", ioctl(SIOCGIFFLAGS) to read its flags, OR in IFF_UP | IFF_RUNNING,
     * and ioctl(SIOCSIFFLAGS) to set them. Best-effort: this needs CAP_NET_ADMIN,
     * so call it before dropping capabilities. */
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("container: loopback");
        return 0;
    }
    struct ifreq f;
    memset(&f,  0, sizeof(struct ifreq));
    strncpy(f.ifr_name, "lo", IFNAMSIZ - 1);
 
    if (ioctl(sock, SIOCGIFFLAGS, &f) < 0) 
    {
        perror("container: loopback");
        close(sock);
        return 0;
    }
    f.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &f) < 0){
        perror("container: loopback");
        close(sock);
        return 0;
    }
    close(sock);
    return 0;
}

int container_net_config(struct container *c)
{
    (void)c;
    /* TODO(student) Part I (--net only): the provided container_net_host_setup()
     * has put an interface named c->net_ifname in this namespace. Configure it
     * (same ioctls as loopback, plus an address and a route):
     *   - ioctl(SIOCSIFADDR)   with c->net_ip;
     *   - ioctl(SIOCSIFNETMASK) with the mask for c->net_prefix;
     *   - ioctl(SIOCSIFFLAGS)  with IFF_UP | IFF_RUNNING;
     *   - add a default route via c->net_gw: fill a `struct rtentry`
     *     (rt_dst/rt_genmask 0.0.0.0, rt_gateway = c->net_gw,
     *     rt_flags = RTF_UP | RTF_GATEWAY) and ioctl(SIOCADDRT).
     * Needs CAP_NET_ADMIN, so container_setup() calls this before the cap drop. */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq f;
    memset(&f, 0, sizeof f);
    strncpy(f.ifr_name, c->net_ifname, IFNAMSIZ - 1);
    struct sockaddr_in *sin = (struct sockaddr_in *)&f.ifr_addr;

    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, c->net_ip, &sin->sin_addr) != 1) goto fail;
    if (ioctl(sock, SIOCSIFADDR, &f) < 0) goto fail;

    /*
    net_prefix is the subnet prefix len
    if there is a prefix then we set it accordingly, otherwise we set it to 0
    
    htonl converts from current int to network representable long
    (32 - c->net_prefix) tells us how much space to allocate on the bottom of the
    address for the submask
    ~0u is just masking the top bits with 1s
    that result is the mask for the subnet addr
    */
    sin->sin_addr.s_addr = c->net_prefix ? htonl(~0u << (32 - c->net_prefix)) : 0;
    if (ioctl(sock, SIOCSIFNETMASK, &f) < 0) goto fail;

    if (ioctl(sock, SIOCGIFFLAGS, &f) < 0) goto fail;
    f.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &f) < 0) goto fail;

    /*
    1. Create an empty routing table entry.
    2. Set the destination and netmask as IPv4.
    3. Set the gateway as IPv4.
    4. Convert the gateway IP from text to binary.
    5. Mark the route as active and using a gateway.
    6. Add the route to the kernel routing table.    
    */
    struct rtentry rt;
    memset(&rt, 0, sizeof rt);
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
    struct sockaddr_in *gw = (struct sockaddr_in *)&rt.rt_gateway;
    gw->sin_family = AF_INET;
    if (inet_pton(AF_INET, c->net_gw, &gw->sin_addr) != 1) goto fail;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    if (ioctl(sock, SIOCADDRT, &rt) < 0) goto fail;

    close(sock);
    return 0;
fail:
    close(sock);
    return -1;
}

int container_seccomp(void)
{
    /* TODO(student) Part III: install a seccomp-BPF filter that blocks a
     * denylist of dangerous syscalls (ptrace, mount, umount2, pivot_root,
     * chroot, setns, unshare, reboot, swapon/swapoff, kexec_load, and the
     * *_module calls) by returning EPERM, and allows everything else.
     *
     * Build a `struct sock_filter[]` with <linux/filter.h> / <linux/seccomp.h>:
     *   1. load seccomp_data.arch and reject a foreign ABI (compare against
     *      AUDIT_ARCH_X86_64 or AUDIT_ARCH_AARCH64 for your build arch);
     *   2. load seccomp_data.nr and, for each denied __NR_*, return
     *      SECCOMP_RET_ERRNO | EPERM;
     *   3. otherwise return SECCOMP_RET_ALLOW.
     * Then prctl(PR_SET_NO_NEW_PRIVS, 1, ...) and
     * syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog). */

    static const int denied[] = {
        __NR_ptrace, __NR_mount, __NR_umount2, __NR_pivot_root, __NR_chroot,
        __NR_setns, __NR_unshare, __NR_reboot, __NR_swapon, __NR_swapoff,
        __NR_kexec_load, __NR_init_module, __NR_finit_module, __NR_delete_module,
    };
    enum { N = sizeof denied / sizeof denied[0] };

    struct sock_filter filter[4 + 2 * N + 1];
    int i = 0;

    /* reject a foreign ABI */
    // loading syscall architecture data
    filter[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, arch));
    // compare with our expected architecture
    filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      SECCOMP_ARCH, 1, 0);            /* match: skip the kill */
    // if they dont match we kill process
    filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                      SECCOMP_RET_KILL_PROCESS);

    /* for each denied syscall, return EPERM */
    // blacklisting syscalls
    filter[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, nr));
    for (int j = 0; j < N; j++) {
        filter[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          (unsigned)denied[j], 0, 1); /* no match: skip the RET */
        filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                          SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }

    /* allow everything else */
    filter[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { .len = (unsigned short)i, .filter = filter };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) return -1;
    return 0;
}

int container_init(struct container *c)
{
    (void)c;
    /* TODO(student) Part IV: this is the container's init, PID 1 in a fresh PID
     * namespace. It runs in the cloned child. Do, in order:
     *   1. wait for the parent to release you: close c->sync[1], then read one
     *      byte from c->sync[0] (it blocks until main's parent writes id-maps
     *      and enters you in the cgroup), then close c->sync[0];
     *   2. call container_setup(c) to isolate this process;
     *   3. fork(). In the child, execvp(c->argv[0], c->argv) -- that is the
     *      command. The parent (you) STAYS as init;
     *   4. loop waitpid(-1, ...): reap every child that dies (adopted orphans
     *      included). Stop when the command itself is reaped; return its exit
     *      status (WEXITSTATUS, or 128+signal if it was killed).
     * The value you return here is what the container exits with. */
    close(c->sync[1]);
    char release;
    if (read(c->sync[0], &release, 1) != 1) {
        perror("container init: read sync");
        return -1;
    }
    close(c->sync[0]);
    if (container_setup(c) < 0) {
        return -1;
    }
    pid_t cmd_pid = fork();
    if (cmd_pid < 0) {
        perror("container init: fork");
        return -1;
    }

    if (cmd_pid == 0) {
        execvp(c->argv[0], c->argv);
        
        perror("container init: execvp");
        _exit(127);
    }

    int status;
    int exit_status = -1;
    pid_t reaped;
    while ((reaped = waitpid(-1, &status, 0)) > 0) {
        if (reaped == cmd_pid) {
            if (WIFEXITED(status)) {
                exit_status = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                exit_status = 128 + WTERMSIG(status);
            }
            break;
        }
    }

    return exit_status;
}

/* ---- the whole lifecycle: main.c calls only this ----------------------- */

static int child_entry(void *arg)
{
    return container_init((struct container *)arg);
}

int container_run(struct container *c)
{
    (void)c;
    /* TODO(student): drive the container's whole lifecycle and return the
     * command's exit status. In order:
     *   1. container_cgroup_init(c)                      (Part V);
     *   2. pipe(c->sync)                                 (the release pipe);
     *   3. clone() a child into fresh namespaces: allocate a stack of
     *      CONTAINER_STACK_SIZE bytes, and clone a small trampoline that calls
     *      container_init(c), with flags container_namespaces() | SIGCHLD.
     *      (clone wants an int(*)(void*); the stack grows down, so pass the
     *      TOP of the buffer: stack + CONTAINER_STACK_SIZE.);
     *   4. container_write_idmaps(c, child)              (Part I);
     *   5. container_cgroup_enter(c, child)              (Part V);
     *   6. if c->net_enabled, call the PROVIDED container_net_host_setup(c, child)
     *      here (after the cgroup step, before releasing the child): it sets up
     *      the bridge + veth and moves one end into the child's netns;
     *   7. release the child: close c->sync[0], write a byte to c->sync[1];
     *   8. waitpid(child): the child (your init) exits with the command's
     *      status; turn that into a 0-255 return value;
     *   9. if c->net_enabled, call container_net_host_teardown(c), then
     *      container_cleanup(c)                          (Part VI);
     *  10. return the status.
     *
     * As shipped this returns 1 and nothing runs. Start here. */

    /* Keep the "container: " prefix on anything you print here: the test
     * harness reads the container's output and skips lines starting with it. */
    if (container_cgroup_init(c) < 0) return -1;
    // make the C groups
    if (pipe(c->sync) < 0) {
        perror("container: pipe");
        return -1;
    }
    // allocate stack and clone child proc into new namespaces
    char *stack = malloc(CONTAINER_STACK_SIZE);
    if (!stack) {
        perror("container: malloc stack");
        return -1;
    }

    pid_t child = clone(child_entry, stack + CONTAINER_STACK_SIZE, container_namespaces() | SIGCHLD, c);
    if (child < 0) {
        perror("container: clone");
        free(stack);
        return -1;
    }

    if (container_write_idmaps(c, child) < 0) return -1;

    if (container_cgroup_enter(c, child) < 0) return -1;

    if (c->net_enabled) {
        if (container_net_host_setup(c, child) < 0) return -1;
    }
    
    //part 4 
    close(c->sync[0]);
    char release = 1;
    if (write(c->sync[1], &release, 1) != 1) {
        perror("container: sync write");
        return -1;
    }
    close(c->sync[1]);

    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("container: waitpid");
        return -1;
    }

    int exit_status = -1;
    if (WIFEXITED(status)) {
        exit_status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_status = 128 + WTERMSIG(status);
    }

    if (c->net_enabled) {
        container_net_host_teardown(c);
    }

    container_cleanup(c);
    free(stack);
    return exit_status;
}

/* ---- Part VI: teardown ------------------------------------------------- */

int container_cleanup(struct container *c)
{
    (void)c;
    /* TODO(student): the child (and its whole subtree) is already reaped, so its
     * cgroup is empty and its mount namespace is gone. Remove the cgroup
     * directory you created (rmdir c->cg_path). Tolerate it already being gone. */
    if (rmdir(c->cg_path) < 0) {
        // Tolerate ENOENT (No such file or directory) if it's already gone
        if (errno != ENOENT) {
            perror("container: rmdir cgroup");
            return -1;
        }
    }
    return 0;
}
