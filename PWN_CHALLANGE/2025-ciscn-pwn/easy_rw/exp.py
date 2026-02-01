#!/usr/bin/env python3
# pyright: reportWildcardImportFromLibrary=false
from pwn import (
    ELF,
    p64,
    p32,
    u32,
    u64,
    FileStructure,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
    os,
    gdb,
    pause,
    log,
    sleep,
)

# 配置
context(os='linux', arch='amd64', log_level='debug')
binary = "./server"

# 远程/本地切换
if args.get("REMOTE"):
    io = remote("127.0.0.1", 8080)
else:
    io = process(binary)
    context.terminal = [os.path.expanduser('~/.local/bin/kitty-gdb')]

# ELF加载
elf = ELF(binary)
libc = elf.libc

# fmt: off
# [+] ========== 常用函数定义 ========== [+]
s       = lambda data               : io.send(data)
sa      = lambda delim, data        : io.sendafter(str(delim), data)
sl      = lambda data               : io.sendline(data)
sla     = lambda delim, data        : io.sendlineafter(str(delim), data)
r       = lambda num=4096           : io.recv(num)
rl      = lambda                    : io.recvline()
ru      = lambda delims, drop=False : io.recvuntil(delims, drop)
itr     = lambda                    : io.interactive()
uu32    = lambda data               : u32(data.ljust(4, b'\x00'))
uu64    = lambda data               : u64(data.ljust(8, b'\x00'))
leak    = lambda name, addr         : log.success('{} ======== > {:#x}'.format(name, addr))
p       = lambda name,data          : print("{} ======== > {}".format(name,data))

# [+] ========== 常用泄露函数 ========== [+]
l64     = lambda                    : u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
l32     = lambda                    : u32(io.recvuntil(b"\xf7")[-4:].ljust(4, b"\x00"))
l64_no  = lambda                    : u64(io.recv(6).ljust(8, b'\x00'))
# fmt: on

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
