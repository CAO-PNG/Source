#!/bin/zsh

# =========================================================
# GDB 快速附加脚本 (参数化)
# 用法: ./gdb_attach.zsh <程序文件名>
# =========================================================

# --- 1. 参数检查与赋值 ---
if [[ -z "$1" ]]; then
    echo "❌ 错误: 请指定要调试的程序文件名。"
    echo "用法: $0 <程序文件名>"
    exit 1
fi

# 程序名 (用于 pidof/pgrep 查找进程)
BINARY_NAME="$1" 
# 完整的程序路径 (用于 GDB 加载符号)
# 假设程序在当前目录，如果不在，请修改路径。
BINARY_PATH="./$1" 

# --- 2. 环境检查 (解决 ptrace 权限问题) ---
# 检查 /proc/sys/kernel/yama/ptrace_scope 的值
PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)

if [[ "$PTRACE_SCOPE" -ne 0 ]]; then
    echo "--------------------------------------------------------"
    echo "⚠️ 警告: 发现 ptrace 权限受限 (yama_ptrace_scope = $PTRACE_SCOPE)"
    echo "【必要步骤】请先在终端执行此命令，否则 GDB Attach 会失败:"
    echo "  sudo sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'"
    echo "--------------------------------------------------------"
fi

# --- 3. 查找 PID ---
# 使用 pgrep -o 查找最老的 (通常是主进程) PID
PID=$(pgrep -o $BINARY_NAME) 

if [[ -z "$PID" ]]; then
    echo "❌ 错误: 进程 '$BINARY_NAME' 未找到或已终止。"
    echo "请确认您的 pwntools 脚本已运行并暂停。"
    exit 1
fi

# --- 4. 启动 GDB ---
echo "✅ 正在附加 GDB 到进程 ($BINARY_PATH, PID: $PID)"
# 使用 -q (安静启动) 和 -p (PID)，并指定程序路径加载符号。
gdb -q $BINARY_PATH -p $PID

# ---------------------------------------------------------
