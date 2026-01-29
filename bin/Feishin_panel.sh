#!/bin/bash

CLASS="feishin"
HIDDEN_WS="99"
# 完整的启动命令
LAUNCH_CMD="feishin --ozone-platform-hint=auto --enable-features=WaylandWindowDecorations --disable-gpu-memory-buffer-video-frames"

# 1. 检查进程是否存在
if ! pgrep -x "$CLASS" >/dev/null; then
    notify-send "Music Panel" "Starting Feishin..."
    # 使用 setsid 开启新会话，防止脚本退出导致程序跟着关掉
    setsid $LAUNCH_CMD > /dev/null 2>&1 &
    exit 0
fi

# 2. 获取当前状态
ACTIVE_WINDOW=$(hyprctl activewindow -j)
ACTIVE_CLASS=$(echo "$ACTIVE_WINDOW" | jq -r '.class // "none"')

# 3. 逻辑判断
if [ "$ACTIVE_CLASS" == "$CLASS" ]; then
    # 已经在当前窗口，送往 99 号
    hyprctl dispatch pin 0
    hyprctl dispatch movetoworkspacesilent $HIDDEN_WS,class:^($CLASS)$
    notify-send "Music Panel" "Hidden to Workspace $HIDDEN_WS" -t 800
else
    # 不在当前窗口（可能在 99 或其他地方），抓取过来
    # 先强制取消一次 pin 以防万一
    hyprctl dispatch movetoworkspace f+0,class:^($CLASS)$
    hyprctl dispatch centerwindow
    hyprctl dispatch focuswindow class:^($CLASS)$
fi
