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

# 使用修复的accurate_checksec函数
accurate_checksec() {
  local binary="$1"

  python3 -c "
import sys
try:
    from pwnlib.elf.elf import ELF
    from pwnlib.util.fiddling import hexdump
    from pwnlib.context import context
    from pwnlib import checksec
except ImportError:
    from pwn import *

# 设置日志级别避免干扰
context.log_level = 'error'

try:
    # 使用checksec函数获取准确信息
    result = checksec('$binary')
    
    # 颜色定义
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    print(f'{BOLD}[*] \"$binary\"{END}')
    
    # 架构信息
    elf = ELF('$binary')
    arch_str = f'{elf.arch}-{elf.bits}-{elf.endian}'
    print(f'    Arch:     {BLUE}{arch_str}{END}')
    
    # 从checksec结果中获取保护信息
    # RELRO
    relro = result.get('RELRO', 'Unknown')
    if 'Full' in str(relro):
        print(f'    RELRO:    {GREEN}Full RELRO{END}')
    elif 'Partial' in str(relro):
        print(f'    RELRO:    {YELLOW}Partial RELRO{END}')
    else:
        print(f'    RELRO:    {RED}No RELRO{END}')
    
    # Stack Canary
    canary = result.get('Canary', 'Unknown')
    if 'Yes' in str(canary):
        print(f'    Stack:    {GREEN}Canary found{END}')
    else:
        print(f'    Stack:    {RED}No canary found{END}')
    
    # NX
    nx = result.get('NX', 'Unknown')
    if 'Yes' in str(nx):
        print(f'    NX:       {GREEN}NX enabled{END}')
    else:
        print(f'    NX:       {RED}NX disabled{END}')
    
    # PIE
    pie = result.get('PIE', 'Unknown')
    if 'Yes' in str(pie):
        print(f'    PIE:      {GREEN}PIE enabled{END}')
    else:
        print(f'    PIE:      {RED}No PIE{END}')
    
    # FORTIFY
    fortify = result.get('FORTIFY', 'Unknown')
    if 'Yes' in str(fortify):
        print(f'    FORTIFY:  {GREEN}Enabled{END}')
    else:
        print(f'    FORTIFY:  {RED}Disabled{END}')
        
except Exception as e:
    # 在异常处理中也定义颜色
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    print(f'{RED}[-] 检查保护失败: {e}{END}')
    print(f'{YELLOW}[!] 尝试使用命令行checksec...{END}')
    import subprocess
    try:
        # 尝试使用 pwn checksec 命令
        output = subprocess.check_output(['pwn', 'checksec', '$binary'], stderr=subprocess.STDOUT, text=True)
        # 为命令行输出添加颜色
        lines = output.strip().split('\n')
        for line in lines:
            if 'Arch:' in line:
                print(f'    {BLUE}{line}{END}')
            elif 'RELRO:' in line:
                if 'Full' in line:
                    print(f'    {GREEN}{line}{END}')
                elif 'Partial' in line:
                    print(f'    {YELLOW}{line}{END}')
                else:
                    print(f'    {RED}{line}{END}')
            elif 'Stack:' in line:
                if 'Canary found' in line:
                    print(f'    {GREEN}{line}{END}')
                else:
                    print(f'    {RED}{line}{END}')
            elif 'NX:' in line:
                if 'NX enabled' in line:
                    print(f'    {GREEN}{line}{END}')
                else:
                    print(f'    {RED}{line}{END}')
            elif 'PIE:' in line:
                if 'PIE enabled' in line:
                    print(f'    {GREEN}{line}{END}')
                else:
                    print(f'    {RED}{line}{END}')
            else:
                print(line)
    except Exception as e2:
        print(f'{RED}[-] 所有检查方法都失败了: {e2}{END}')
"
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

  # 2. 检查保护 - 使用修复的accurate_checksec函数
  info "检查二进制文件保护:"
  echo "=================================="
  accurate_checksec "$BINARY"
  echo "=================================="

  # 3. 生成exp.py - 修复快捷函数问题
  info "生成exp.py模板..."

  # 修复的exp.py模板
  cat >exp.py <<EOF
#!/usr/bin/env python3
from lazypwn import *

# 配置
binary = "$BINARY"
libc_path = None
remote_host = None
remote_port = None
arch = "amd64"

io = PwnHelper(
    binary_path=binary,
    libc_path=libc_path,
    remote_host=remote_host,
    remote_port=remote_port,
    arch=arch,
    log_level="debug"
)

# 定义快捷函数（通过io对象调用）
def s(data): return io.s(data)
def sa(delim, data): return io.sa(delim, data)
def sl(data): return io.sl(data)
def sla(delim, data): return io.sla(delim, data)
def r(num=4096): return io.r(num)
def ru(delims, drop=True): return io.ru(delims, drop)
def itr(): return io.itr()
def uu32(data): return io.uu32(data)
def uu64(data): return io.uu64(data)
def leak(name, addr): return io.leak(name, addr)
def l32(): return io.l32()
def l64(): return io.l64()
def debug(script=None): return io.debug(script)
def bug(script=None): return io.bug(script)

def exp():
    # [+]====== Exploit Start =======[+]
    io.connect()
    
    # 在这里开始编写你的利用代码
    # 使用上面定义的快捷函数，例如:
    # sla(b"choice:", b"1")
    # leak_addr = l64()
    # leak("main", leak_addr)

exp()
io.itr()
EOF

  # 检查文件是否生成成功
  if [ -f "exp.py" ]; then
    chmod +x exp.py
    success "exp.py生成成功"
  else
    error "生成exp.py失败"
    exit 1
  fi

  echo ""
  success "初始化完成！"
  echo "下一步: python3 exp.py"
}

# 运行主函数
main "$@"
