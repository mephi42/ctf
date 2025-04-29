#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define MOUNT_POINT "/tmp/capyflag.XXXXXX"
#define FLAG_PATH "/flag"

int main() {
    char mount_buf[PATH_MAX] = MOUNT_POINT;
    char flag_path[PATH_MAX];
    char flag_contents[1024] = {0};
    char *mount_dir = NULL;
    int flag_fd = -1;
    int ret = EXIT_FAILURE;
    int len;

    // Create mount point directory
    mount_dir = mkdtemp(mount_buf);
    if (!mount_dir) {
        perror("Failed to create temporary directory");
        goto out;
    }

    // Mount the 9p filesystem
    if (mount("host", mount_dir, "9p", 0, "trans=virtio") != 0) {
        perror("Failed to mount 9p filesystem");
        goto out_rmdir;
    }

    // Construct path to flag file
    len = snprintf(flag_path, sizeof(flag_path), "%s%s", mount_dir, FLAG_PATH);
    if (len < 0 || (size_t)len >= sizeof(flag_path)) {
        fprintf(stderr, "Flag path too long\n");
        goto out_umount;
    }

    // Open and read the flag file
    flag_fd = open(flag_path, O_RDONLY);
    if (flag_fd < 0) {
        perror("Failed to open flag file");
        goto out_umount;
    }

    ssize_t bytes_read = read(flag_fd, flag_contents, sizeof(flag_contents) - 1);
    if (bytes_read < 0) {
        perror("Failed to read flag file");
        goto out_close;
    }

    // Print the message and flag
    printf("CAPY-9000 EMP cannon deactivated\n");
    printf("Flag: %s", flag_contents);

    ret = EXIT_SUCCESS;

out_close:
    close(flag_fd);
out_umount:
    umount(mount_dir);
out_rmdir:
    rmdir(mount_dir);
out:
    return ret;
} 