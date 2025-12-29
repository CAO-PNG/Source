#!/bin/bash

# pwninit - PWN题目快速初始化脚本
# 作者: CAO-PNG

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 打印函数
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 显示用法
usage() {
  echo "用法: $0 <二进制文件>"
  echo "示例:"
  echo "  $0 ./chall"
}

# 检查是否在虚拟环境中
check_venv() {
  if [ -n "$VIRTUAL_ENV" ]; then
    info "当前已在虚拟环境中: $(basename "$VIRTUAL_ENV")"
    return 0
  else
    warning "当前不在虚拟环境中，请先运行: ctf"
    return 1
  fi
}
# 主函数
main() {
  # 检查参数
  if [ $# -eq 0 ]; then
    usage
    exit 1
  fi

  BINARY="$1"

  # 检查文件是否存在
  if [ ! -f "$BINARY" ]; then
    error "文件不存在: $BINARY"
    exit 1
  fi

  # 0. 检查是否在虚拟环境中
  if ! check_venv; then
    warning "请先手动进入虚拟环境: ctf"
    warning "然后再次运行: $0 $BINARY"
    exit 1
  fi

  # 1. 给二进制文件加权限
  info "给二进制文件添加执行权限..."
  chmod +x "$BINARY"
  success "权限添加成功: $BINARY"

  # 2. 自动运行checksec
  echo "[INFO] 检查二进制文件保护:"
  echo "=================================="
  checksec "$BINARY"
  echo "=================================="

  # 3. 生成exp.py - 使用更符合CTF习惯的模板
  info "生成exp.py模板..."

  # 新的exp.py模板
  cat >exp.py <<EOF
#!/usr/bin/env python3
from pwn import *
from LibcSearcher import *

# 配置
context(os='linux', arch='amd64', log_level='debug')
binary = "./$BINARY"

# 远程/本地切换
if args.get("REMOTE"):
    io = remote("127.0.0.1", 8080)
else:
    io = process(binary)
    context.terminal = [
        os.path.expanduser('~/.local/bin/kitty-gdb'),
        os.path.abspath(binary), 
        str(io.pid)                
    ]
# ELF加载
elf = ELF(binary)
libc = ELF("/usr/lib/libc.so.6")

# [+] ========== 常用函数定义 ========== [+]
s       = lambda data               : io.send(data)
sa      = lambda delim, data        : io.sendafter(str(delim), data)
sl      = lambda data               : io.sendline(data)
sla     = lambda delim, data        : io.sendlineafter(str(delim), data)
r       = lambda num=4096           : io.recv(num)
rl      = lambda                    : io.recvline()
ru      = lambda delims, drop=False : io.recvuntil(delims, drop)
itr     = lambda                    : io.interactive()
uu32    = lambda data               : u32(data.ljust(4, b'\\x00'))
uu64    = lambda data               : u64(data.ljust(8, b'\\x00'))
leak    = lambda name, addr         : log.success('{} ======== > {:#x}'.format(name, addr))
p       = lambda name,data          : print("{} ======== > {}".format(name,data))

# [+] ========== 常用泄露函数 ========== [+]
l64     = lambda                    : u64(io.recvuntil(b"\\x7f")[-6:].ljust(8, b"\\x00"))
l32     = lambda                    : u32(io.recvuntil(b"\\xf7")[-4:].ljust(4, b"\\x00"))
l64_no  = lambda                    : u64(io.recv(6).ljust(8, b'\\x00'))

def bug():
  gdb.attach(io)
  pause()

def P():
  pause()

def pulsh(): 
  sleep(0.5)
#  [+] ========== Exploit 开始 ========== [+]
def exp():
    
exp()
itr()
EOF

  # 检查文件是否生成成功
  if [ -f "exp.py" ]; then
    chmod +x exp.py
    success "exp.py生成成功"
  else
    error "生成exp.py失败"
    exit 1
  fi

  success "初始化完成！"
}

# 运行主函数
main "$@"
