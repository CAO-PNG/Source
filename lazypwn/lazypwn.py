#!/usr/bin/env python3
"""
LazyPwn - A simplified pwn exploitation library for CTF competitions
"""

from pwn import *
import os

class PwnHelper:
    def __init__(self, binary_path, libc_path=None, remote_host=None, remote_port=None, arch="amd64", log_level="debug"):
        """
        Initialize PwnHelper
        
        Args:
            binary_path: Binary file path
            libc_path: Libc path (optional)
            remote_host: Remote host address (optional) 
            remote_port: Remote port (optional)
            arch: Architecture, default amd64
            log_level: Log level, default debug
        """
        self.binary_path = binary_path
        self.libc_path = libc_path
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.arch = arch
        
        # Set context
        context(os="linux", arch=arch, log_level=log_level)
        
        # Load ELF
        self.elf = ELF(binary_path, checksec=False)
        
        # Load libc
        if libc_path and os.path.exists(libc_path):
            self.libc = ELF(libc_path, checksec=False)
        else:
            self.libc = None
        
        # Connection settings
        self.io = None
        self.is_remote = False
        
    def connect(self, use_remote=None):
        """
        Establish connection
        
        Args:
            use_remote: Whether to use remote connection, auto-detect if None
        """
        if use_remote is None:
            use_remote = (self.remote_host is not None and self.remote_port is not None)
        
        if use_remote and self.remote_host and self.remote_port:
            self.io = remote(self.remote_host, self.remote_port)
            self.is_remote = True
            log.info(f"Connected to {self.remote_host}:{self.remote_port}")
        else:
            self.io = process(self.binary_path)
            self.is_remote = False
            log.info(f"Started process: {self.binary_path}")
        
        return self.io
    
    # Send functions
    def s(self, data):
        """Send data"""
        return self.io.send(data)
    
    def sa(self, delim, data):
        """Send data after receiving delim"""
        return self.io.sendafter(str(delim), data)
    
    def sl(self, data):
        """Send line"""
        return self.io.sendline(data)
    
    def sla(self, delim, data):
        """Send line after receiving delim"""
        return self.io.sendlineafter(str(delim), data)
    
    # Receive functions  
    def r(self, num):
        """Receive specified number of bytes"""
        return self.io.recv(num)
    
    def ru(self, delims, drop=False):
        """Receive until delims"""
        return self.io.recvuntil(delims, drop)
    
    def rl(self):
        """Receive line"""
        return self.io.recvline()
    
    # Interactive functions
    def interactive(self):
        """Enter interactive mode"""
        return self.io.interactive()
    
    def itr(self):
        """Alias for interactive"""
        return self.interactive()
    
    # Utility functions
    def uu32(self, data):
        """Convert data to 32-bit unsigned integer"""
        return u32(data.ljust(4, b'\x00'))
    
    def uu64(self, data):
        """Convert data to 64-bit unsigned integer"""
        return u64(data.ljust(8, b'\x00'))
    
    def leak(self, name, addr):
        """Print leaked address information"""
        return log.success('{} is---->{:#x}'.format(name, addr))
    
    def l64(self):
        """Leak 64-bit address (common format)"""
        return u64(self.io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
    
    def l32(self):
        """Leak 32-bit address (common format)"""
        return u32(self.io.recvuntil("\xf7")[-4:].ljust(4, b"\x00"))
    
    def l64_suffix(self, suffix=b"\x7f"):
        """Leak 64-bit address with custom suffix"""
        return u64(self.io.recvuntil(suffix)[-6:].ljust(8, b"\x00"))
    
    def l32_suffix(self, suffix=b"\xf7"):
        """Leak 32-bit address with custom suffix"""
        return u32(self.io.recvuntil(suffix)[-4:].ljust(4, b"\x00"))
    
    # Debug functions
    def debug(self, script=None):
        """Attach gdb debugger"""
        if not self.is_remote:
            gdb.attach(self.io, script)
            pause()
        else:
            log.warning("Cannot attach gdb to remote connection")
    
    def bug(self, script=None):
        """Alias for debug"""
        self.debug(script)
    
    # Symbol address retrieval
    def sym(self, symbol_name):
        """Get symbol address"""
        return self.elf.symbols.get(symbol_name, 0)
    
    def got(self, symbol_name):
        """Get GOT address"""
        return self.elf.got.get(symbol_name, 0)
    
    def plt(self, symbol_name):
        """Get PLT address"""
        return self.elf.plt.get(symbol_name, 0)
    
    # ROP related
    def find_gadget(self, gadget):
        """Find gadget"""
        rop = ROP(self.elf)
        return rop.find_gadget([gadget])
    
    # Offset calculation
    def libc_base_leak(self, leak_addr, offset):
        """Calculate libc base from leaked address"""
        if self.libc:
            return leak_addr - self.libc.symbols.get(offset, 0)
        else:
            log.warning("Libc not loaded")
            return None
    
    def elf_base_leak(self, leak_addr, offset):
        """Calculate ELF base from leaked address"""
        return leak_addr - self.elf.symbols.get(offset, 0)

# Convenience functions
def connect_binary(binary_path, remote_host=None, remote_port=None, **kwargs):
    """Quickly connect to binary"""
    ph = PwnHelper(binary_path, remote_host=remote_host, remote_port=remote_port, **kwargs)
    return ph.connect()

def quick_debug(io, script=None):
    """Quickly attach debugger"""
    if not isinstance(io, remote):
        gdb.attach(io, script)
        pause()
    else:
        log.warning("Cannot attach gdb to remote connection")

# Payload generation functions
def p64_payload(*addresses):
    """Generate 64-bit packed payload"""
    return b''.join(p64(addr) for addr in addresses)

def p32_payload(*addresses):
    """Generate 32-bit packed payload"""
    return b''.join(p32(addr) for addr in addresses)

def cyclic_find_pattern(io, pattern_length=100):
    """Generate and find cyclic pattern"""
    pattern = cyclic(pattern_length)
    io.sendline(pattern)
    return pattern

# Automation function
def auto_exploit(helper, payload, leak_func=None):
    """
    Automated exploitation template
    
    Args:
        helper: PwnHelper instance
        payload: Attack payload
        leak_func: Leak function (optional)
    """
    # Establish connection
    helper.connect()
    
    # Execute leak function if provided
    if leak_func:
        leak_addr = leak_func(helper)
        helper.leak("Leaked address", leak_addr)
    
    # Send payload
    helper.sl(payload)
    
    # Enter interactive mode
    helper.interactive()
