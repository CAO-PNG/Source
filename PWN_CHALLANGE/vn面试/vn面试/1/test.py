from pwn import *
import subprocess

# 尝试不同的终端配置
terminal_configs = [
    ['gnome-terminal', '--'],
    ['xterm', '-e'],
    ['konsole', '-e'],
    ['xfce4-terminal', '-x'],
    ['terminator', '-x'],
    ['tilix', '-e'],
    ['alacritty', '-e'],  # 添加 alacritty
    ['urxvt', '-e'],      # 添加 urxvt
]

def find_working_terminal():
    for config in terminal_configs:
        try:
            # 测试终端是否能正常工作
            result = subprocess.run(config + ['echo', 'test'], 
                                  timeout=2, capture_output=True)
            if result.returncode == 0:
                print(f"找到可用的终端: {config[0]}")
                return config
        except Exception as e:
            print(f"终端 {config[0]} 测试失败: {e}")
            continue
    return None

# 测试终端
working_terminal = find_working_terminal()
if not working_terminal:
    print("没有找到可用终端，使用手动调试模式")
    context.terminal = None
else:
    context.terminal = working_terminal
    print(f"已设置终端为: {working_terminal[0]}")

# 使用示例
def exp():
    io = process('./pwn')
    
    if context.terminal:
        try:
            print("尝试自动附加 gdb...")
            gdb.attach(io, '''
            break main
            continue
            ''')
            print("gdb 附加成功!")
        except Exception as e:
            print(f"自动附加失败: {e}")
            print(f"请手动运行: gdb -p {io.pid}")
    else:
        print(f"进程 PID: {io.pid}")
        print("请手动运行以下命令进行调试:")
        print(f"gdb -p {io.pid}")
        input("按回车继续执行 exploit...")
    
    # 你的 exploit 代码
    io.interactive()

if __name__ == '__main__':
    exp()
