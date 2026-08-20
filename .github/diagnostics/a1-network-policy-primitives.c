#define _GNU_SOURCE

#include <errno.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static void print_result(const char *name, long result, int saved_errno) {
    printf("%s result=%ld errno=%d\n", name, result, saved_errno);
}

struct mount_attr_probe {
    unsigned long long attr_set;
    unsigned long long attr_clear;
    unsigned long long propagation;
    unsigned long long userns_fd;
};

static void run_mount_probe(const char *name, int namespaces) {
    pid_t child = fork();
    if (child == 0) {
        if (unshare(namespaces) != 0) {
            dprintf(STDOUT_FILENO, "%s step=unshare errno=%d\n", name, errno);
            _exit(1);
        }
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
            dprintf(STDOUT_FILENO, "%s step=mount-private errno=%d\n", name, errno);
            _exit(2);
        }
        const char *root = "/opt/appwritework/verification-a1/probe";
        if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) != 0) {
            dprintf(STDOUT_FILENO, "%s step=mount-bind errno=%d\n", name, errno);
            _exit(3);
        }
        struct mount_attr_probe attributes = {
            .attr_set = MS_RDONLY,
            .attr_clear = 0,
            .propagation = 0,
            .userns_fd = 0,
        };
        errno = 0;
        long readonly_result = syscall(
            SYS_mount_setattr,
            AT_FDCWD,
            root,
            AT_RECURSIVE,
            &attributes,
            sizeof(attributes)
        );
        dprintf(
            STDOUT_FILENO,
            "%s step=mount-setattr result=%ld errno=%d\n",
            name,
            readonly_result,
            errno
        );
        _exit(readonly_result == 0 ? 0 : 4);
    }
    if (child < 0) {
        printf("%s step=fork errno=%d\n", name, errno);
        return;
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("%s exit=%d\n", name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

int main(void) {
    unsigned int action = SECCOMP_RET_USER_NOTIF;
    errno = 0;
    long seccomp_result = syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
    print_result("seccomp_user_notif", seccomp_result, errno);

    errno = 0;
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    print_result("pidfd_open_self", pidfd, errno);
    if (pidfd >= 0) {
        errno = 0;
        int copied_fd = (int)syscall(SYS_pidfd_getfd, pidfd, STDOUT_FILENO, 0);
        print_result("pidfd_getfd_self_stdout", copied_fd, errno);
        if (copied_fd >= 0) {
            close(copied_fd);
        }
        close(pidfd);
    }

    unsigned char source = 7;
    unsigned char target = 0;
    struct iovec local = { .iov_base = &target, .iov_len = 1 };
    struct iovec remote = { .iov_base = &source, .iov_len = 1 };
    errno = 0;
    long process_vm_result = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    print_result("process_vm_readv_self", process_vm_result, errno);
    printf("process_vm_readv_value=%u\n", (unsigned int)target);

    FILE *resolv = fopen("/etc/resolv.conf", "r");
    printf("resolv_conf_readable=%d\n", resolv != NULL);
    if (resolv != NULL) {
        fclose(resolv);
    }

    run_mount_probe("isolate_deny", CLONE_NEWNS | CLONE_NEWNET);
    run_mount_probe("isolate_registry_only", CLONE_NEWNS);

    pid_t child = fork();
    if (child == 0) {
        _exit(unshare(CLONE_NEWNET) == 0 ? 0 : errno);
    }
    if (child < 0) {
        print_result("fork_for_newnet", -1, errno);
        return 0;
    }
    int status = 0;
    errno = 0;
    long waited = waitpid(child, &status, 0);
    print_result("waitpid_newnet", waited, errno);
    if (waited == child && WIFEXITED(status)) {
        printf("unshare_newnet_exit=%d\n", WEXITSTATUS(status));
    } else {
        printf("unshare_newnet_exit=-1\n");
    }
    return 0;
}
