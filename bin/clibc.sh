 #!/bin/zsh

# 检查参数数量
if [[ $# -lt 2 ]]; then
  echo "Usage:"
  echo "  clibc <bin> <ver>               # 模式 1: 使用 glibc-all-in-one"
  echo "  clibc <bin> L <ld> <libc> [ext] # 模式 2: 手动指定文件"
  echo "  clibc <bin> D <dir_path>        # 模式 3: 自动扫描目录 (推荐) 但是需要自己创建文件夹"
  exit 1
fi

BINARY="$1"
BINARY_REALPATH=$(realpath "$BINARY")
BINARY_DIR=$(dirname "$BINARY_REALPATH")
BACKUP_FILE="${BINARY}.bak"

# 1. 备份与恢复逻辑
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Creating backup: $BACKUP_FILE"
  cp "$BINARY" "$BACKUP_FILE"
else
  echo "Restoring from backup: $BACKUP_FILE"
  cp -f "$BACKUP_FILE" "$BINARY"
fi

# 2. 检测二进制架构
FILE_INFO=$(file "$BINARY")
if [[ "$FILE_INFO" == *"ELF 32-bit"* ]]; then
  ARCH_DIR="i386"; DEFAULT_LD="ld-linux.so.2"
elif [[ "$FILE_INFO" == *"ELF 64-bit"* ]]; then
  ARCH_DIR="amd64"; DEFAULT_LD="ld-linux-x86-64.so.2"
else
  echo "Error: Not a valid ELF binary"; exit 1
fi

LOCAL_LIBS_DIR="$BINARY_DIR/libs"
mkdir -p "$LOCAL_LIBS_DIR"

# ==========================================================
# 模式 D：目录自动扫描
# ==========================================================
if [[ "$2" = "D" ]]; then
  SRC_DIR=$(realpath "$3")
  echo "Scanning directory: $SRC_DIR"

  # 如果源目录不是当前的 libs，则同步文件
  if [[ "$SRC_DIR" != "$(realpath "$LOCAL_LIBS_DIR")" ]]; then
    echo "Copying libraries to ./libs..."
    cp -rn "$SRC_DIR"/* "$LOCAL_LIBS_DIR/" 2>/dev/null
  fi

  # 寻找 LD: 找可执行的 ld-*.so
  LD_FILE=$(find "$LOCAL_LIBS_DIR" -type f -name "ld-*.so*" -executable | head -n 1)

  # 寻找 Libc: 找文件名匹配且是 ELF 的文件 (不再强求有 GLIBC 字样)
  LIBC_FILE=$(find "$LOCAL_LIBS_DIR" -type f \( -name "libc-*.so*" -o -name "libc.so.6" \) | xargs file | grep "shared object" | cut -d: -f1 | head -n 1)

  SELECTED_VERSION="Directory Scan ($SRC_DIR)"
  VERSION_DIR="\$ORIGIN/libs"

# ==========================================================
# 模式 L：手动指定
# ==========================================================
elif [[ "$2" = "L" ]]; then
  LD_SRC="$3"; LIBC_SRC="$4"
  shift 2
  for F in "$@"; do
    cp -f "$(realpath "$F")" "$LOCAL_LIBS_DIR/"
  done
  LD_FILE="$LOCAL_LIBS_DIR/$(basename "$LD_SRC")"
  LIBC_FILE="$LOCAL_LIBS_DIR/$(basename "$LIBC_SRC")"
  SELECTED_VERSION="Manual L Mode"
  VERSION_DIR="\$ORIGIN/libs"

# ==========================================================
# 默认模式：glibc-all-in-one
# ==========================================================
else
  LIB_VERSION="$2"
  GLIBC_AIO_DIR="${GLIBC_AIO_DIR:-$HOME/CTF_PWN/tools/glibc-all-in-one/}"
  LIBS_DIR="$GLIBC_AIO_DIR/libs"
  LIST_FILE="$GLIBC_AIO_DIR/list"

  # 寻找匹配的版本
  SELECTED_VERSION=$(grep "$LIB_VERSION" "$LIST_FILE" | grep "_$ARCH_DIR" | head -n 1)
  if [ -z "$SELECTED_VERSION" ]; then
    echo "Error: Version $LIB_VERSION ($ARCH_DIR) not found in glibc-all-in-one list"
    exit 1
  fi

  VERSION_DIR="$LIBS_DIR/$SELECTED_VERSION"
  LD_FILE="$VERSION_DIR/$DEFAULT_LD"
  LIBC_FILE="$VERSION_DIR/libc.so.6"

  # 如果没下载就下载 (保持原脚本逻辑)
  if [ ! -d "$VERSION_DIR" ]; then
    echo "Downloading $SELECTED_VERSION..."
    cd "$GLIBC_AIO_DIR" && ./download "$SELECTED_VERSION" && cd -
  fi
fi

# ==========================================================
# 执行 Patch
# ==========================================================
if [ -z "$LD_FILE" ] || [ -z "$LIBC_FILE" ]; then
  echo "Error: Could not find valid LD or Libc."
  echo "Found LD: $LD_FILE"
  echo "Found Libc: $LIBC_FILE"
  exit 1
fi

# 关键：修复本地 libs 里的 libc.so.6 链接，确保它指向真正的 libc 文件
if [[ "$2" == "D" || "$2" == "L" ]]; then
  LIBC_NAME=$(basename "$LIBC_FILE")
  rm -f "$LOCAL_LIBS_DIR/libc.so.6"
  ln -sf "$LIBC_NAME" "$LOCAL_LIBS_DIR/libc.so.6"
  echo "Fixed link: libs/libc.so.6 -> $LIBC_NAME"
fi

echo "--------------------------------------"
echo "Target: $BINARY"
echo "LD: $LD_FILE"
echo "RPATH: $VERSION_DIR"
echo "--------------------------------------"

# 执行补丁：使用 --force-rpath 确保覆盖现有的 RUNPATH
patchelf --set-interpreter "$LD_FILE" --force-rpath --set-rpath "$VERSION_DIR" "$BINARY"

# 验证
if ldd "$BINARY" | grep -q "not found"; then
  echo "Warning: Some dependencies are still missing!"
  ldd "$BINARY" | grep "not found"
else
  echo "Success: Patched successfully with $SELECTED_VERSION"
fi
