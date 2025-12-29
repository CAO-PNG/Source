#!/bin/bash

# --- 配置区域 ---
# Windows 分区的自动挂载路径（根据你 findmnt 的结果）
WIN_MOUNT_PATH="/run/media/source/新加卷"
# VHDX 文件的相对路径
VHDX_REL_PATH="pwn/VM/wsl/Ubuntu/ext4.vhdx"
# 最终 WSL 挂载到的目标目录
TARGET_MOUNT_POINT="/mnt/wsl_root"
# NBD 设备
NBD_DEV="/dev/nbd0"

VHDX_FULL_PATH="${WIN_MOUNT_PATH}/${VHDX_REL_PATH}"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此脚本"
  exit 1
fi

do_mount() {
  # 1. 检查 Windows 分区是否就绪
  if [ ! -d "$WIN_MOUNT_PATH" ]; then
    echo "错误: 未找到 Windows 挂载点 $WIN_MOUNT_PATH，请先在文件管理器中点击打开该硬盘。"
    exit 1
  fi

  if [ ! -f "$VHDX_FULL_PATH" ]; then
    echo "错误: 找不到 VHDX 文件: $VHDX_FULL_PATH"
    exit 1
  fi

  # 2. 加载 nbd 模块
  if ! lsmod | grep -q "^nbd "; then
    echo "加载 nbd 内核模块..."
    modprobe nbd max_part=8
  fi

  # 3. 连接 VHDX
  echo "正在连接 VHDX 文件到 $NBD_DEV..."
  qemu-nbd --connect="$NBD_DEV" "$VHDX_FULL_PATH"

  # 等待设备就绪
  sleep 1

  # 4. 挂载分区
  # WSL2 通常只有一个分区，直接挂载 /dev/nbd0，如果不行则尝试 /dev/nbd0p1
  mkdir -p "$TARGET_MOUNT_POINT"
  echo "正在挂载到 $TARGET_MOUNT_POINT..."

  if mount "$NBD_DEV" "$TARGET_MOUNT_POINT" 2>/dev/null; then
    echo "✅ 挂载成功！你现在可以访问 $TARGET_MOUNT_POINT 了。"
  elif mount "${NBD_DEV}p1" "$TARGET_MOUNT_POINT" 2>/dev/null; then
    echo "✅ 挂载成功 (分区1)！你现在可以访问 $TARGET_MOUNT_POINT 了。"
  else
    echo "❌ 挂载失败，请检查文件系统是否损坏。"
    qemu-nbd --disconnect "$NBD_DEV"
    exit 1
  fi
}

do_umount() {
  echo "正在卸载 $TARGET_MOUNT_POINT..."
  umount "$TARGET_MOUNT_POINT"

  echo "正在断开 $NBD_DEV..."
  qemu-nbd --disconnect "$NBD_DEV"

  echo "✅ 卸载完成。"
}

case "$1" in
mount)
  do_mount
  ;;
umount | unmount)
  do_umount
  ;;
*)
  echo "用法: sudo $0 {mount|umount}"
  exit 1
  ;;
esac
