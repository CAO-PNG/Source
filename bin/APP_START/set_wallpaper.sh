#!/bin/bash
# 动态获取显示器HDMI-A-3的分辨率并设置mpvpaper
sleep 3
# 使用 hyprctl 获取指定显示器的分辨率
RESOLUTION=$(hyprctl monitors | awk '/HDMI-A-3/{f=1} f && /resolution:/{print $2; exit}')
# 启动mpvpaper并应用铺满滤镜
mpvpaper -o "loop --vf=no-crop,scale=${RESOLUTION}:force_original_aspect_ratio=increase,crop=${RESOLUTION}" HDMI-A-3 /home/source/puter/丹瑾-剑-战斗.mp4
