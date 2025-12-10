#!/bin/zsh

# 检查参数数量
if [[ $# -ne 2 ]] && [[ $# -ne 4 ]]; then
  echo "Usage:"
  echo "  clibc <binary_name> <libc_version>                    # 使用 glibc-all-in-one 中的版本"
  echo "  clibc <binary_name> L <ld_path> <libc_path>          # 使用指定的 ld 和 libc 文件"
  echo "Example:"
  echo "  clibc ./pwn 2.35"
  echo "  clibc ./pwn L /path/to/ld-2.35.so /path/to/libc-2.35.so"
  exit 1
fi

BINARY="$1"

# 创建或恢复原始文件的备份
BACKUP_FILE="${BINARY}.bak"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Creating backup: $BACKUP_FILE"
  cp "$BINARY" "$BACKUP_FILE"
else
  echo "Restoring from backup: $BACKUP_FILE"
  cp -f "$BACKUP_FILE" "$BINARY"
fi

# 检测目标程序架构
FILE_INFO=$(file "$BINARY")
if [[ $? -ne 0 ]]; then
  echo "Error: Failed to get file information for '$BINARY'"
  exit 1
fi

if [[ "$FILE_INFO" == *"ELF 32-bit"* ]]; then
  ARCH_DIR="i386"
  DEFAULT_LD="ld-linux.so.2"
elif [[ "$FILE_INFO" == *"ELF 64-bit"* ]]; then
  ARCH_DIR="amd64"
  DEFAULT_LD="ld-linux-x86-64.so.2"
else
  echo "Error: Not a valid ELF binary"
  exit 1
fi

# 模式判断：如果是 L 模式
if [[ $# -eq 4 ]] && [[ "$2" = "L" ]]; then
  LD_PATH="$3"
  LIBC_PATH="$4"

  # 检查指定的文件是否存在
  if [ ! -f "$LD_PATH" ]; then
    echo "Error: LD file '$LD_PATH' not found!"
    exit 1
  fi

  if [ ! -f "$LIBC_PATH" ]; then
    echo "Error: Libc file '$LIBC_PATH' not found!"
    exit 1
  fi

  # 检查文件架构是否匹配
  LD_ARCH=$(file "$LD_PATH")
  LIBC_ARCH=$(file "$LIBC_PATH")

  if [[ "$FILE_INFO" == *"32-bit"* ]] && [[ ! "$LD_ARCH" == *"32-bit"* ]]; then
    echo "Error: Binary is 32-bit but LD file is not 32-bit"
    exit 1
  fi

  if [[ "$FILE_INFO" == *"64-bit"* ]] && [[ ! "$LD_ARCH" == *"64-bit"* ]]; then
    echo "Error: Binary is 64-bit but LD file is not 64-bit"
    exit 1
  fi

  # 获取 libc 文件所在目录的绝对路径
  LIBC_DIR=$(dirname "$(realpath "$LIBC_PATH")")
  LD_FILE=$(realpath "$LD_PATH")
  LIBC_FILE=$(realpath "$LIBC_PATH")

  # 设置版本目录为 libc 所在目录
  VERSION_DIR="$LIBC_DIR"

  # 在 L 模式下，确保 libc.so.6 符号链接存在
  LIBC_SO6="$VERSION_DIR/libc.so.6"
  if [ ! -e "$LIBC_SO6" ]; then
    echo "Creating libc.so.6 symlink in $VERSION_DIR"
    ln -sf "$(basename "$LIBC_PATH")" "$LIBC_SO6"
  fi

  echo "Using custom libc:"
  echo "  LD: $LD_PATH"
  echo "  Libc: $LIBC_PATH"
  echo "  Directory: $VERSION_DIR"

  # 设置 SELECTED_VERSION 用于最后的显示
  SELECTED_VERSION="custom"

else
  # 原模式：使用 glibc-all-in-one
  LIB_VERSION="$2"

  # 设置 glibc-all-in-one 路径
  GLIBC_AIO_DIR="${GLIBC_AIO_DIR:-$HOME/CTF_PWN/tools/glibc-all-in-one/}"
  LIBS_DIR="$GLIBC_AIO_DIR/libs"
  LIST_FILE="$GLIBC_AIO_DIR/list"
  OLD_LIST_FILE="$GLIBC_AIO_DIR/old_list"

  # 检查目标二进制文件
  if [ ! -f "$BINARY" ]; then
    echo "Error: Binary file '$BINARY' not found!"
    exit 1
  fi

  # 检查 glibc-all-in-one 目录结构
  if [ ! -d "$GLIBC_AIO_DIR" ]; then
    echo "Error: glibc-all-in-one directory not found at $GLIBC_AIO_DIR"
    exit 1
  fi

  if [ ! -d "$LIBS_DIR" ]; then
    mkdir -p "$LIBS_DIR"
  fi

  # 从 list 和 old_list 中收集所有匹配的版本
  ALL_VERSIONS=()
  if [ -f "$LIST_FILE" ]; then
    while IFS= read -r line; do
      line="${line//$'\r'/}"
      [ -z "$line" ] && continue
      if [[ "$line" == *"$LIB_VERSION"* && "$line" == *"_$ARCH_DIR" ]]; then
        ALL_VERSIONS+=("$line")
      fi
    done <"$LIST_FILE"
  fi

  if [ -f "$OLD_LIST_FILE" ]; then
    while IFS= read -r line; do
      line="${line//$'\r'/}"
      [ -z "$line" ] && continue
      if [[ "$line" == *"$LIB_VERSION"* && "$line" == *"_$ARCH_DIR" ]]; then
        ALL_VERSIONS+=("$line")
      fi
    done <"$OLD_LIST_FILE"
  fi

  # 如果没有找到任何版本
  if [ ${#ALL_VERSIONS[@]} -eq 0 ]; then
    echo "Error: No glibc versions found for $LIB_VERSION ($ARCH_DIR)"
    exit 1
  fi

  # 如果只有一个版本，直接使用
  if [ ${#ALL_VERSIONS[@]} -eq 1 ]; then
    SELECTED_VERSION="${ALL_VERSIONS[1]}" # zsh数组从1开始
    echo "Using: $SELECTED_VERSION"
  else
    # 显示可用版本列表 - 使用zsh的for循环
    echo "Available glibc versions:"
    for ((i = 1; i <= ${#ALL_VERSIONS[@]}; i++)); do
      echo "  $i. ${ALL_VERSIONS[$i]}"
    done

    # 获取用户选择
    read "selection?Select (1-${#ALL_VERSIONS[@]}): "
    if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#ALL_VERSIONS[@]} ]; then
      echo "Invalid selection"
      exit 1
    fi

    SELECTED_VERSION="${ALL_VERSIONS[$selection]}"
  fi

  # 检查版本是否已存在本地
  VERSION_DIR="$LIBS_DIR/$SELECTED_VERSION"
  if [ ! -d "$VERSION_DIR" ]; then
    echo "Downloading $SELECTED_VERSION..."

    # 确定下载命令
    DOWNLOAD_CMD=""
    if [ -f "$LIST_FILE" ] && grep -q "^$SELECTED_VERSION$" "$LIST_FILE" 2>/dev/null; then
      DOWNLOAD_CMD="$GLIBC_AIO_DIR/download"
    elif [ -f "$OLD_LIST_FILE" ] && grep -q "^$SELECTED_VERSION$" "$OLD_LIST_FILE" 2>/dev/null; then
      DOWNLOAD_CMD="$GLIBC_AIO_DIR/download_old"
    else
      echo "Error: Version not found in list files"
      exit 1
    fi

    # 执行下载
    if ! "$DOWNLOAD_CMD" "$SELECTED_VERSION"; then
      echo "Error: Download failed"
      exit 1
    fi
  fi

  # 确定动态链接器
  if [ -f "$VERSION_DIR/$DEFAULT_LD" ]; then
    LD_FILE="$VERSION_DIR/$DEFAULT_LD"
  else
    # 尝试查找任何 ld-*.so 文件
    LD_FILE=$(find "$VERSION_DIR" -maxdepth 1 -name 'ld-*.so' -print -quit)
    if [ ! -f "$LD_FILE" ]; then
      echo "Error: Dynamic linker not found"
      exit 1
    fi
  fi
fi

# 执行patchelf命令
if ! patchelf --set-interpreter "$LD_FILE" --set-rpath "$VERSION_DIR" "$BINARY"; then
  echo "Error: patchelf failed"
  exit 1
fi

# 验证修改是否成功
if ! file "$BINARY" | grep -q "dynamically linked" && ! file "$BINARY" | grep -q "动态可执行文件"; then
  echo "Error: Binary is not dynamically linked after patching. Restoring original binary."
  cp -f "$BACKUP_FILE" "$BINARY"
  exit 1
fi

if [[ $# -eq 4 ]] && [[ "$2" = "L" ]]; then
  echo "Success: Patched $BINARY with custom libc from $VERSION_DIR"
else
  echo "Success: Patched $BINARY with $SELECTED_VERSION"
fi
