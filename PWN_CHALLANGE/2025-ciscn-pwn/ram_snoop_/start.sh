#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd  ./rootfs.cpio \
    -monitor /dev/null \
    -append "root=/dev/ram rdinit=/init console=ttyS0 oops=panic panic=1 quiet rodata=off " \
    -cpu qemu64,+smep,+smap \
    -smp cores=2,threads=1 \
    -nographic \
    -snapshot
