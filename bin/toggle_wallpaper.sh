#!/bin/bash

# --- 配置区域 ---
# 你可以使用 Steam Workshop ID，也可以使用本地文件夹的绝对路径
# 请确保路径正确
WP_HDMI="3364621880" # HDMI-A-3 使用的壁纸 (ID或路径)
WP_EDP="3146507587"  # eDP-1 使用的壁纸 (ID或路径)

# --- 执行区域 ---
# 1. 先彻底杀死旧进程（防止重启时进程残留）
killall -9 linux-wallpaperengine 2>/dev/null

# 2. 启动新的进程
# 根据你提供的文档，使用 --screen-root 来指定不同显示器的壁纸
linux-wallpaperengine --screen-root HDMI-A-3 "$WP_HDMI" --screen-root eDP-1 "$WP_EDP"
