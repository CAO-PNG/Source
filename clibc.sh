#!/bin/zsh

# 检查参数数量
if [ $# -ne 2 ]; then
    echo "Usage: clibc <binary_name> <libc_version>"
    echo "Example: clibc ./pwn 2.35"
    exit 1
fi

BINARY="$1"
LIB_VERSION="$2"

# 设置 glibc-all-in-one 路径
GLIBC_AIO_DIR="${GLIBC_AIO_DIR:-$HOME/TOOLS/glibc-all-in-one}"
LIBS_DIR="$GLIBC_AIO_DIR/libs"
LIST_FILE="$GLIBC_AIO_DIR/list"
OLD_LIST_FILE="$GLIBC_AIO_DIR/old_list"

# 检查目标二进制文件
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary file '$BINARY' not found!"
    exit 1
fi

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
    done < "$LIST_FILE"
fi

if [ -f "$OLD_LIST_FILE" ]; then
    while IFS= read -r line; do
        line="${line//$'\r'/}"
        [ -z "$line" ] && continue
        if [[ "$line" == *"$LIB_VERSION"* && "$line" == *"_$ARCH_DIR" ]]; then
            ALL_VERSIONS+=("$line")
        fi
    done < "$OLD_LIST_FILE"
fi

# 如果没有找到任何版本
if [ ${#ALL_VERSIONS[@]} -eq 0 ]; then
    echo "Error: No glibc versions found for $LIB_VERSION ($ARCH_DIR)"
    exit 1
fi

# 如果只有一个版本，直接使用
if [ ${#ALL_VERSIONS[@]} -eq 1 ]; then
    SELECTED_VERSION="${ALL_VERSIONS[1]}"
    echo "Using: $SELECTED_VERSION"
else
    # 显示可用版本列表
    echo "Available glibc versions:"
    for i in {1..${#ALL_VERSIONS[@]}}; do
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

echo "Success: Patched $BINARY with $SELECTED_VERSION"
